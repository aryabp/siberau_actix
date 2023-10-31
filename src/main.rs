mod filesystem;
mod search;
mod services;

use actix_cors::Cors;
use actix_web::{web::Data, App, HttpServer};
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use filesystem::explorer::{
    create_directory, create_file, delete_file, download_file, open_directory, rename_file,
    upload_file, delete_folder,
};

use filesystem::volume::{get_volumes, Timer, Volume};
use search::search_directory;
use serde::{Deserialize, Serialize};

use services::{change_user, delete_user, login_user, otp_form, otp_self, register_user, OtpData, OtpDataForm, list_role, permissions};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fs::File, io::BufReader};

use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

#[derive(Serialize, Deserialize, Clone)]
pub struct CachedPath {
    #[serde(rename = "p")]
    file_path: String,
    #[serde(rename = "t")]
    file_type: String,
}

pub type VolumeCache = HashMap<String, Vec<CachedPath>>;

#[derive(Default)]
pub struct AppState {
    system_cache: HashMap<String, VolumeCache>,
}

pub type StateSafe = Arc<Mutex<AppState>>;
pub struct AppStatex {
    db: Pool<Postgres>,
}

fn cors_middleware() -> Cors {
    Cors::default()
        .allow_any_origin() // Replace with your frontend's URL
        .allow_any_method()
        .allow_any_header()
        .max_age(3600) // Specify the maximum age of preflight requests (in seconds)
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub enum Role {
    Kasatsiber,
    Kasiops,
    KatimCegah,
    KatimTanggul,
    KatimTindak,
    KatimPulih,
    StaffCegah,
    StaffTanggul,
    StaffTindak,
    #[default]
    StaffPulih,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Kasatsiber => write!(f, "Kasatsiber"),
            Role::Kasiops => write!(f, "Kasiops"),
            Role::KatimCegah => write!(f, "KatimCegah"),
            Role::KatimTanggul => write!(f, "KatimTanggul"),
            Role::KatimTindak => write!(f, "KatimTindak"),
            Role::KatimPulih => write!(f, "KatimPulih"),
            Role::StaffCegah => write!(f, "StaffCegah"),
            Role::StaffTanggul => write!(f, "StaffTanggul"),
            Role::StaffTindak => write!(f, "StaffTindak"),
            Role::StaffPulih => write!(f, "StaffPulih"),
        }
    }
}

impl Role {
    pub fn from_string(role_str: &str) -> Option<Role> {
        match role_str {
            "Kasatsiber" => Some(Role::Kasatsiber),
            "Kasiops" => Some(Role::Kasiops),
            "KatimCegah" => Some(Role::KatimCegah),
            "KatimTanggul" => Some(Role::KatimTanggul),
            "KatimTindak" => Some(Role::KatimTindak),
            "KatimPulih" => Some(Role::KatimPulih),
            "StaffCegah" => Some(Role::StaffCegah),
            "StaffTanggul" => Some(Role::StaffTanggul),
            "StaffTindak" => Some(Role::StaffTindak),
            "StaffPulih" => Some(Role::StaffPulih),
            _ => None,
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let config = load_rustls_config();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");
    let cache_mem = Arc::new(Mutex::new(AppState::default()));

    let mut vec_otp_form = Vec::new();
    vec_otp_form.push(OtpDataForm::default());
    let otpstate_form = Arc::new(Mutex::new(vec_otp_form));
    let mut vec_otp = Vec::new();
    vec_otp.push(OtpData::default());
    let otpstate = Arc::new(Mutex::new(vec_otp));
    let mut volumes = Vec::new();
    volumes.push(Volume::default());
    let volume = Arc::new(Mutex::new(volumes));

    let timer = Arc::new(Mutex::new(Timer::default()));

    HttpServer::new(move || {
        App::new()
            .wrap(cors_middleware())
            .app_data(Data::new(AppStatex { db: pool.clone() }))
            .app_data(Data::new(cache_mem.clone()))
            .app_data(Data::new(volume.clone()))
            .app_data(Data::new(timer.clone()))
            .app_data(Data::new(otpstate.clone()))
            .app_data(Data::new(otpstate_form.clone()))
            .service(permissions)
            .service(list_role)
            .service(login_user)
            .service(register_user)
            .service(otp_form)
            .service(otp_self)
            .service(change_user)
            .service(delete_user)
            .service(get_volumes)
            .service(open_directory)
            .service(search_directory)
            .service(create_file)
            .service(create_directory)
            .service(rename_file)
            .service(delete_file)
            .service(delete_folder)
            .service(download_file)
            .service(upload_file)
    })
    .bind_rustls_021("192.168.100.77:8080", config)?
    .run()
    .await
}

fn load_rustls_config() -> rustls::ServerConfig {
    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("key.pem").unwrap());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}