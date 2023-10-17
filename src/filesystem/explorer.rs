use std::fs;
use std::fs::read_dir;
use std::ops::Deref;
use std::path::Path;
use actix_files::NamedFile;

use notify::event::CreateKind;
use std::io::Write;
use actix_multipart::Multipart;
use futures::{StreamExt, TryStreamExt};

use crate::filesystem::cache::FsEventHandler;
//use crate::filesystem::fs_utils;
use crate::filesystem::fs_utils::get_mount_point;
use crate::filesystem::volume::DirectoryChild;
use crate::StateSafe;
use serde::Deserialize;


use actix_web::{
    post, 
    web::{self,Data, Json},
    Responder, HttpResponse, Result
};

#[derive(Deserialize)]
pub struct CreateCommonBody {
    pub path: String
}
#[derive(Deserialize)]
pub struct CreateSwitchBody {
    pub old_path: String,
    pub new_path: String,
}

/// Searches and returns the files in a given directory. This is not recursive.
#[post("/opendirectory")]
pub async fn open_directory(body: Json<CreateCommonBody>) -> Result<HttpResponse, actix_web::Error> {
    
    let directory_result = read_dir(&body.path);
    
    match directory_result {
        Ok(directory) => {
            let directory_contents: Vec<DirectoryChild> = directory
                .filter_map(|entry| {
                    match entry {
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
                    }
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
pub async fn create_file(state_mux: Data<StateSafe>, body: Json<CreateCommonBody>) -> impl Responder {
    let mount_point_str = get_mount_point(String::from(&body.path)).unwrap_or_default();

    let fs_event_manager = FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
    fs_event_manager.handle_create(CreateKind::File, Path::new(&body.path));

    let res = fs::File::create(String::from(&body.path));
    match res {
        Ok(_) => {
            HttpResponse::Ok()
        },
        Err(_) => HttpResponse::BadRequest(),
    }
}

#[post("/createdirectory")]
pub async fn create_directory(state_mux: Data<StateSafe>, body: Json<CreateCommonBody>) -> impl Responder {
    let mount_point_str = get_mount_point(String::from(&body.path)).unwrap_or_default();

    let fs_event_manager = FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
    fs_event_manager.handle_create(CreateKind::Folder, Path::new(&body.path));

    let res = fs::create_dir(String::from(&body.path));
    match res {
        Ok(_) => {
            HttpResponse::Ok()
        },
        Err(_) => HttpResponse::BadRequest(),
    }
}

#[post("/renamefile")]
pub async fn rename_file(state_mux: Data<StateSafe>, body: Json<CreateSwitchBody>) -> impl Responder {
    let mount_point_str = get_mount_point(String::from(&body.old_path)).unwrap_or_default();

    let mut fs_event_manager = FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
    fs_event_manager.handle_rename_from(Path::new(&body.old_path));
    fs_event_manager.handle_rename_to(Path::new(&body.new_path));

    let res = fs::rename(&body.old_path, &body.new_path);
    match res {
        Ok(_) => {
            HttpResponse::Ok()
        },
        Err(_) => HttpResponse::BadRequest(),
    }
}

#[post("/deletefile")]
pub async fn delete_file(state_mux: Data<StateSafe>, body: Json<CreateCommonBody>) -> impl Responder {
    let mount_point_str = get_mount_point(String::from(&body.path)).unwrap_or_default();

    let fs_event_manager = FsEventHandler::new(state_mux.deref().deref().clone(), mount_point_str.into());
    fs_event_manager.handle_delete(Path::new(&body.path));

    let res = fs::remove_file(&body.path);
        match res {
            Ok(_) => {
                HttpResponse::Ok()
            },
            Err(_) => HttpResponse::BadRequest(),
        }
}

#[post("/downloadfile")]
pub async fn download_file(body: Json<CreateCommonBody>) -> Result<NamedFile> {
    Ok(NamedFile::open(&body.path)?)
}

async fn save_file(mut payload: Multipart) -> Option<bool> {
    // iterate over multipart stream
    while let Ok(Some(mut field)) = payload.try_next().await {
        
        let content_type = field.content_disposition();
        let file_path = content_type.get_name().unwrap();
        let file_name = content_type.get_filename().unwrap();
        if file_path.is_empty() && file_name.is_empty()  {
            break
        }
        let filepath: String = format!("{}/{}", file_path,file_name);

        // File::create is blocking operation, use threadpool
        
        let mut f = web::block(|| std::fs::File::create(filepath))
            .await
            .unwrap()
            .unwrap();
        
        // Field in turn is stream of *Bytes* object
        while let Some(chunk) = field.next().await {
            let data = chunk.unwrap();
            // filesystem operations are blocking, we have to use threadpool
            f = web::block(move || f.write_all(&data).map(|_| f))
                .await
                .unwrap()
                .unwrap();
        }
    }
    Some(true)
}

#[post("/uploadfile")]
pub async fn upload_file(payload: Multipart) -> impl Responder{
    let upload_status = save_file(payload).await;

    match upload_status {
        Some(true) => {
            HttpResponse::Ok()
                .content_type("text/plain")
                .body("update_succeeded")
        }
        _ => HttpResponse::BadRequest()
            .content_type("text/plain")
            .body("update_failed"),
    }
}