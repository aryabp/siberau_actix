mod filesystem;
mod search;
mod services;

use actix_cors::Cors;
use actix_web::{web::Data, App, HttpServer};
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use filesystem::explorer::{
    create_directory, create_file, delete_file, download_file, open_directory, rename_file,
    upload_file,
};

use filesystem::volume::{get_volumes, Timer, Volume};
use search::search_directory;
use serde::{Deserialize, Serialize};

use services::{change_user, delete_user, login_user, otp_form, otp_self, register_user, OtpData, OtpDataForm};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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
impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print the field values using the `write!` macro
        write!(f, "AppState {{ system_cache: {:?} }}", self.system_cache)
    }
}

impl std::fmt::Debug for CachedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CachedPath {{ file_path: {:?}, file_type: {:?} }}",
            self.file_path, self.file_type
        )
    }
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
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
            .service(download_file)
            .service(upload_file)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
