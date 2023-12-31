use crate::filesystem::volume::DirectoryChild;
use crate::StateSafe;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use std::path::Path;
use std::time::Instant;
use serde::Deserialize;
use actix_web::{
    post, 
    web::{Data, Json},
    Responder, HttpResponse
};

#[derive(Deserialize)]
pub struct CreateSearchBody {
    pub query: String,
    pub search_directory: String,
    pub mount_pnt: String,
    pub extension: String,
    pub accept_files: bool,
    pub accept_directories: bool,
}

const MINIMUM_SCORE: i16 = 20;

/// Checks if the filename passes the extension filter, also checks if extension filter is provided.
fn passed_extension(filename: &str, extension: &String) -> bool {
    if extension.is_empty() {
        return true;
    }
    filename.ends_with(extension.as_str())
}

/// Gives a filename a fuzzy matcher score
/// Returns 1000 if there is an exact match for prioritizing
fn score_filename(matcher: &SkimMatcherV2, filename: &str, query: &str) -> i16 {
    if filename == query {
        return 1000;
    }
    matcher.fuzzy_match(filename, query).unwrap_or(0) as i16
}

fn check_file(
    matcher: &SkimMatcherV2,
    accept_files: bool,
    filename: &String,
    file_path: &String,
    extension: &String,
    query: String,
    results: &mut Vec<DirectoryChild>,
    fuzzy_scores: &mut Vec<i16>,
) {
    if !accept_files {
        return;
    }
    if !passed_extension(filename, extension) {
        return;
    }

    let filename_path = Path::new(filename);
    let cleaned_filename = filename_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");

    let score = score_filename(matcher, cleaned_filename, query.as_str());
    if score < MINIMUM_SCORE {
        return;
    }

    results.push(DirectoryChild::File(
        filename.to_string(),
        file_path.to_string(),
    ));
    fuzzy_scores.push(score);
}

/// Reads the cache and does a fuzzy search for a directory.
/// Takes into account the filters provided.
/// Returns the results ONLY when the entire volume is searched
#[post("/search")]
pub async fn search_directory(
    state_mux: Data<StateSafe>,
    body: Json<CreateSearchBody>,
) -> impl Responder {
    
    let start_time = Instant::now();

    let mut results: Vec<_> = Vec::new();
    let mut fuzzy_scores: Vec<i16> = Vec::new();
    let matcher = SkimMatcherV2::default().smart_case();

    let state = state_mux.lock().unwrap();
    let query = body.query.to_lowercase();

    match state.system_cache.get(&body.mount_pnt){
        Some(system_cache) => {
            for (filename, paths) in system_cache {
                for path in paths {
                    let file_type = &path.file_type;
                    let file_path = &path.file_path;
        
                    if !file_path.starts_with(&body.search_directory) {
                        continue;
                    }
        
                    if file_type == "file" {
                        check_file(
                            &matcher,
                            body.accept_files,
                            filename,
                            file_path,
                            &body.extension,
                            query.clone(),
                            &mut results,
                            &mut fuzzy_scores,
                        );
        
                        continue;
                    }
        
                    if !body.accept_directories {
                        continue;
                    }
        
                    let score = score_filename(&matcher, filename, &query);
                    if score < MINIMUM_SCORE {
                        continue;
                    }
        
                    results.push(DirectoryChild::Directory(
                        filename.to_string(),
                        file_path.to_string(),
                    ));
                    fuzzy_scores.push(score);
                }
            }
        
            let end_time = Instant::now();
            println!("Elapsed time: {:?}", end_time - start_time);
            // Sort by best match first.
            let mut tuples: Vec<(usize, _)> = fuzzy_scores.iter().enumerate().collect();
            tuples.sort_by(|a, b| b.1.cmp(a.1));
        
            let sorted_result:Vec<DirectoryChild> = tuples
                .into_iter()
                .map(|(index, _)| results[index].clone())
                .collect();
            HttpResponse::Ok().json(sorted_result)
        },
        None => HttpResponse::InternalServerError().json("Volume haven't cached yet")
    }
    
}
