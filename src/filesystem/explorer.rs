use std::fs::{self, read_dir};
use std::io::Write;
use std::iter::Iterator;
use std::ops::Deref;
use std::path::Path;

use actix_files::NamedFile;
use actix_multipart::Multipart;
use actix_web::HttpRequest;
use futures::{StreamExt, TryStreamExt};
use notify::event::CreateKind;

use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use sha2::Sha256;

use crate::filesystem::cache::FsEventHandler;
use crate::filesystem::fs_utils::get_mount_point;
use crate::filesystem::volume::DirectoryChild;
use crate::services::TokenClaims;
use crate::{Role, StateSafe};

use serde::Deserialize;

use actix_web::{
    post,
    web::{self, Data, Json},
    HttpResponse, Responder, Result,
};

#[derive(Deserialize)]
pub struct CreateCommonBody {
    pub path: String,
    pub jwt: String,
}
#[derive(Deserialize)]
pub struct CreateSwitchBody {
    pub old_path: String,
    pub new_path: String,
    pub jwt: String,
}

/// Searches and returns the files in a given directory. This is not recursive.
#[post("/opendirectory")]
pub async fn open_directory(
    body: Json<CreateCommonBody>,
) -> Result<HttpResponse, actix_web::Error> {
    let directory_result = read_dir(&body.path);
    match directory_result {
        Ok(directory) => {
            let directory_contents: Vec<DirectoryChild> = directory
                .filter_map(|entry| match entry {
                    Ok(entry) => {
                        let file_name = entry.file_name().to_string_lossy().to_string();
                        let entry_is_file = entry.file_type().ok().map_or(false, |ft| ft.is_file());
                        let entry_path = entry.path().to_string_lossy().to_string();

                        if entry_is_file {
                            Some(DirectoryChild::File(file_name, entry_path))
                        } else {
                            Some(DirectoryChild::Directory(file_name, entry_path))
                        }
                    }
                    Err(_) => None,
                })
                .collect();

            let json_response = serde_json::to_string(&directory_contents)?;

            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(json_response))
        }
        Err(_) => {
            // Handle the error, such as returning an error response
            Ok(HttpResponse::InternalServerError().finish())
        }
    }
}

#[post("/createfile")]
pub async fn create_file(
    state_mux: Data<StateSafe>,
    body: Json<CreateCommonBody>,
) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };
    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claims: TokenClaims = fe;
            match claims.role {
                Role::Kasatsiber | Role::Kasiops => {
                    HttpResponse::BadRequest().json("Invalid Authority")
                }
                Role::KatimCegah | Role::StaffCegah => {
                    let dr = std::env::var("CEGAH_DIRECTORY").expect("SET directory a");
                    let adr = std::env::var("ALT_CEGAH_DIRECTORY").expect("SET directory b");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_create_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTanggul | Role::StaffTanggul => {
                    let dr = std::env::var("TANGGUL_DIRECTORY").expect("SET directory c");
                    let adr = std::env::var("ALT_TANGGUL_DIRECTORY").expect("SET directory d");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_create_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTindak | Role::StaffTindak => {
                    let dr = std::env::var("TINDAK_DIRECTORY").expect("SET directory e");
                    let adr = std::env::var("ALT_TINDAK_DIRECTORY").expect("SET directory f");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_create_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimPulih | Role::StaffPulih => {
                    let dr = std::env::var("PULIH_DIRECTORY").expect("SET directory g");
                    let adr = std::env::var("ALT_PULIH_DIRECTORY").expect("SET directory h");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_create_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Invalid JWT Token"),
    }
}
fn do_create_file(state_mux: Data<StateSafe>, body: Json<CreateCommonBody>) -> HttpResponse {
    if !state_mux.lock().unwrap().system_cache.is_empty() {
        let mount_point_str = get_mount_point(String::from(&body.path)).unwrap_or_default();

        let fs_event_manager =
            FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
        fs_event_manager.handle_create(CreateKind::File, Path::new(&body.path));

        let res = fs::File::create(String::from(&body.path));
        match res {
            Ok(_) => HttpResponse::Ok().json("success"),
            Err(_) => HttpResponse::BadRequest().json("error"),
        }
    } else {
        HttpResponse::InternalServerError().json("error")
    }
}

#[post("/createdirectory")]
pub async fn create_directory(
    state_mux: Data<StateSafe>,
    body: Json<CreateCommonBody>,
) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };
    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claims: TokenClaims = fe;
            match claims.role {
                Role::Kasatsiber | Role::Kasiops => {
                    HttpResponse::BadRequest().json("Invalid Authority")
                }
                Role::KatimCegah | Role::StaffCegah => {
                    let dr = std::env::var("CEGAH_DIRECTORY").expect("SET directory a");
                    let adr = std::env::var("ALT_CEGAH_DIRECTORY").expect("SET directory b");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_create_directory(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTanggul | Role::StaffTanggul => {
                    let dr = std::env::var("TANGGUL_DIRECTORY").expect("SET directory c");
                    let adr = std::env::var("ALT_TANGGUL_DIRECTORY").expect("SET directory d");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_create_directory(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTindak | Role::StaffTindak => {
                    let dr = std::env::var("TINDAK_DIRECTORY").expect("SET directory e");
                    let adr = std::env::var("ALT_TINDAK_DIRECTORY").expect("SET directory f");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_create_directory(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimPulih | Role::StaffPulih => {
                    let dr = std::env::var("PULIH_DIRECTORY").expect("SET directory g");
                    let adr = std::env::var("ALT_PULIH_DIRECTORY").expect("SET directory h");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_create_directory(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Invalid JWT Token"),
    }
}
fn do_create_directory(state_mux: Data<StateSafe>, body: Json<CreateCommonBody>) -> HttpResponse {
    if !state_mux.lock().unwrap().system_cache.is_empty() {
        let mount_point_str = get_mount_point(String::from(&body.path)).unwrap_or_default();

        let fs_event_manager =
            FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
        fs_event_manager.handle_create(CreateKind::Folder, Path::new(&body.path));

        let res = fs::create_dir(String::from(&body.path));
        match res {
            Ok(_) => HttpResponse::Ok().json("success"),
            Err(_) => HttpResponse::BadRequest().json("error"),
        }
    } else {
        HttpResponse::InternalServerError().json("error")
    }
}

#[post("/renamefile")]
pub async fn rename_file(
    state_mux: Data<StateSafe>,
    body: Json<CreateSwitchBody>,
) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };
    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claims: TokenClaims = fe;
            match claims.role {
                Role::Kasatsiber | Role::Kasiops => {
                    HttpResponse::BadRequest().json("Invalid Authority")
                }
                Role::KatimCegah | Role::StaffCegah => {
                    let dr = std::env::var("CEGAH_DIRECTORY").expect("SET directory a");
                    let adr = std::env::var("ALT_CEGAH_DIRECTORY").expect("SET directory b");
                    match body.new_path[..dr.len()] == dr || body.new_path[..adr.len()] == adr {
                        true => do_rename_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTanggul | Role::StaffTanggul => {
                    let dr = std::env::var("TANGGUL_DIRECTORY").expect("SET directory c");
                    let adr = std::env::var("ALT_TANGGUL_DIRECTORY").expect("SET directory d");
                    match body.new_path[..dr.len()] == dr || body.new_path[..adr.len()] == adr {
                        true => do_rename_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTindak | Role::StaffTindak => {
                    let dr = std::env::var("TINDAK_DIRECTORY").expect("SET directory e");
                    let adr = std::env::var("ALT_TINDAK_DIRECTORY").expect("SET directory f");
                    match body.new_path[..dr.len()] == dr || body.new_path[..adr.len()] == adr {
                        true => do_rename_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimPulih | Role::StaffPulih => {
                    let dr = std::env::var("PULIH_DIRECTORY").expect("SET directory g");
                    let adr = std::env::var("ALT_PULIH_DIRECTORY").expect("SET directory h");
                    match body.new_path[..dr.len()] == dr || body.new_path[..adr.len()] == adr {
                        true => do_rename_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Invalid JWT Token"),
    }
}
fn do_rename_file(state_mux: Data<StateSafe>, body: Json<CreateSwitchBody>) -> HttpResponse {
    if !state_mux.lock().unwrap().system_cache.is_empty() {
        let mount_point_str = get_mount_point(String::from(&body.old_path)).unwrap_or_default();
        let mut fs_event_manager =
            FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
        fs_event_manager.handle_rename_from(Path::new(&body.old_path));
        fs_event_manager.handle_rename_to(Path::new(&body.new_path));

        let res = fs::rename(&body.old_path, &body.new_path);
        match res {
            Ok(_) => HttpResponse::Ok().json("success"),
            Err(_) => HttpResponse::BadRequest().json("error"),
        }
    } else {
        HttpResponse::InternalServerError().json("error")
    }
}

#[post("/deletefile")]
pub async fn delete_file(
    state_mux: Data<StateSafe>,
    body: Json<CreateCommonBody>,
) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };
    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claims: TokenClaims = fe;
            match claims.role {
                Role::Kasatsiber | Role::Kasiops => {
                    HttpResponse::BadRequest().json("Invalid Authority")
                }
                Role::KatimCegah | Role::StaffCegah => {
                    let dr = std::env::var("CEGAH_DIRECTORY").expect("SET directory a");
                    let adr = std::env::var("ALT_CEGAH_DIRECTORY").expect("SET directory b");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_delete_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTanggul | Role::StaffTanggul => {
                    let dr = std::env::var("TANGGUL_DIRECTORY").expect("SET directory c");
                    let adr = std::env::var("ALT_TANGGUL_DIRECTORY").expect("SET directory d");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_delete_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTindak | Role::StaffTindak => {
                    let dr = std::env::var("TINDAK_DIRECTORY").expect("SET directory e");
                    let adr = std::env::var("ALT_TINDAK_DIRECTORY").expect("SET directory f");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_delete_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimPulih | Role::StaffPulih => {
                    let dr = std::env::var("PULIH_DIRECTORY").expect("SET directory g");
                    let adr = std::env::var("ALT_PULIH_DIRECTORY").expect("SET directory h");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_delete_file(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Invalid JWT Token"),
    }
}
fn do_delete_file(state_mux: Data<StateSafe>, body: Json<CreateCommonBody>) -> HttpResponse {
    if !state_mux.lock().unwrap().system_cache.is_empty() {
        let mount_point_str = get_mount_point(String::from(&body.path)).unwrap_or_default();

        let fs_event_manager =
            FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
        fs_event_manager.handle_delete(Path::new(&body.path));
        match fs::remove_file(&body.path) {
            Ok(_) => HttpResponse::Ok().json("success"),
            Err(_) => HttpResponse::BadRequest().json("error"),
        }
    } else {
        HttpResponse::InternalServerError().json("error")
    }
}

#[post("/deletefolder")]
pub async fn delete_folder(
    state_mux: Data<StateSafe>,
    body: Json<CreateCommonBody>,
) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };
    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claims: TokenClaims = fe;
            match claims.role {
                Role::Kasatsiber | Role::Kasiops => {
                    HttpResponse::BadRequest().json("Invalid Authority")
                }
                Role::KatimCegah | Role::StaffCegah => {
                    let dr = std::env::var("CEGAH_DIRECTORY").expect("SET directory a");
                    let adr = std::env::var("ALT_CEGAH_DIRECTORY").expect("SET directory b");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_delete_folder(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTanggul | Role::StaffTanggul => {
                    let dr = std::env::var("TANGGUL_DIRECTORY").expect("SET directory c");
                    let adr = std::env::var("ALT_TANGGUL_DIRECTORY").expect("SET directory d");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_delete_folder(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTindak | Role::StaffTindak => {
                    let dr = std::env::var("TINDAK_DIRECTORY").expect("SET directory e");
                    let adr = std::env::var("ALT_TINDAK_DIRECTORY").expect("SET directory f");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_delete_folder(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimPulih | Role::StaffPulih => {
                    let dr = std::env::var("PULIH_DIRECTORY").expect("SET directory g");
                    let adr = std::env::var("ALT_PULIH_DIRECTORY").expect("SET directory h");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_delete_folder(state_mux, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Invalid JWT Token"),
    }
}
fn do_delete_folder(state_mux: Data<StateSafe>, body: Json<CreateCommonBody>) -> HttpResponse {
    if !state_mux.lock().unwrap().system_cache.is_empty() {
        let mount_point_str = get_mount_point(String::from(&body.path)).unwrap_or_default();

        let fs_event_manager =
            FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
        fs_event_manager.handle_delete(Path::new(&body.path));
        match fs::remove_dir_all(&body.path) {
            Ok(_) => HttpResponse::Ok().json("success"),
            Err(_) => HttpResponse::BadRequest().json("error"),
        }
    } else {
        HttpResponse::InternalServerError().json("error")
    }
}

#[post("/downloadfile")]
pub async fn download_file(req: HttpRequest, body: Json<CreateCommonBody>) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };
    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claims: TokenClaims = fe;
            match claims.role {
                Role::Kasatsiber | Role::Kasiops => {
                    HttpResponse::BadRequest().json("Invalid Authority")
                }
                Role::KatimCegah | Role::StaffCegah => {
                    let dr = std::env::var("CEGAH_DIRECTORY").expect("SET directory a");
                    let adr = std::env::var("ALT_CEGAH_DIRECTORY").expect("SET directory b");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_download_file(req, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTanggul | Role::StaffTanggul => {
                    let dr = std::env::var("TANGGUL_DIRECTORY").expect("SET directory c");
                    let adr = std::env::var("ALT_TANGGUL_DIRECTORY").expect("SET directory d");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_download_file(req, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimTindak | Role::StaffTindak => {
                    let dr = std::env::var("TINDAK_DIRECTORY").expect("SET directory e");
                    let adr = std::env::var("ALT_TINDAK_DIRECTORY").expect("SET directory f");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_download_file(req, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
                Role::KatimPulih | Role::StaffPulih => {
                    let dr = std::env::var("PULIH_DIRECTORY").expect("SET directory g");
                    let adr = std::env::var("ALT_PULIH_DIRECTORY").expect("SET directory h");
                    match body.path[..dr.len()] == dr || body.path[..adr.len()] == adr {
                        true => do_download_file(req, body),
                        false => HttpResponse::BadRequest().json("Invalid Authority"),
                    }
                }
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Invalid JWT Token"),
    }
}
fn do_download_file(req: HttpRequest, body: Json<CreateCommonBody>) -> HttpResponse {
    match NamedFile::open(&body.path) {
        Ok(fe) => NamedFile::into_response(fe, &req),
        Err(_) => HttpResponse::NotImplemented().json("can't download folder"),
    }
}

#[post("/uploadfile")]
pub async fn upload_file(state_mux: Data<StateSafe>, payload: Multipart) -> impl Responder {
    let upload_status = save_file(state_mux, payload).await;

    match upload_status {
        Some(true) => HttpResponse::Ok()
            .content_type("text/plain")
            .body("update_succeeded"),
        _ => HttpResponse::BadRequest()
            .content_type("text/plain")
            .body("update_failed"),
    }
}
async fn save_file(state_mux: Data<StateSafe>, mut payload: Multipart) -> Option<bool> {
    // iterate over multipart stream
    //if !state_mux.lock().unwrap().system_cache.is_empty() {
        while let Ok(Some(mut field)) = payload.try_next().await {
            let content_type = field.content_disposition();
            let file_path = content_type.get_name().unwrap();
            let file_name = content_type.get_filename().unwrap();
            if file_path.is_empty() && file_name.is_empty() {
                break;
            }
            let filepath: String = format!("{}/{}", file_path, file_name);

            // File::create is blocking operation, use threadpool
            let mount_point_str = get_mount_point(String::from(&filepath)).unwrap_or_default();
            let fs_event_manager =
                FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
            fs_event_manager.handle_create(CreateKind::File, Path::new(&filepath));

            let mut f = web::block(|| std::fs::File::create(filepath))
                .await
                .unwrap()
                .unwrap();

            // Field in turn is stream of *Bytes* object
            while let Some(chunk) = field.next().await {
                let data: web::Bytes = chunk.unwrap();
                // filesystem operations are blocking, we have to use threadpool
                f = web::block(move || f.write_all(&data).map(|_| f))
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
        Some(true)
        /* 
    } else {
        Some(false)
    }*/
}

