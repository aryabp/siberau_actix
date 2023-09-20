use actix_web::{web::Data, App, HttpServer};
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use actix_cors::Cors;
mod services;
use services::{create_user_article, fetch_user_articles, fetch_users, login_user, register_user};

pub struct AppState {
    db: Pool<Postgres>
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

    HttpServer::new(move || {
        App::new()
            .wrap(cors_middleware())
            .app_data(Data::new(AppState { db: pool.clone() }))
            .service(fetch_users)
            .service(fetch_user_articles)
            .service(create_user_article)
            .service(login_user)
            .service(register_user)
    })
    .bind(("192.168.101.145", 8080))?
    .run()
    .await
}