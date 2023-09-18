use actix_web::{
    get, post, 
    web::{Data, Json, Path},
    Responder, HttpResponse
};
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow};
use crate::AppState;
use argonautica::{Hasher, Verifier};
use hmac::{Hmac,Mac};
use jwt::SignWithKey;
use sha2::Sha256;





#[derive(Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    id_user: i32,
    username: String,
    email: String,
    phone_number: String,
    role: String,
}

#[derive(Serialize, FromRow)]
struct CustomJwt{
    jwt: String,
    status: String,
}

#[derive(Serialize, FromRow)]
struct User {
    id: i32,
    first_name: String,
    last_name: String,
}

#[derive(Serialize, FromRow)]
struct Article {
    id: i32,
    title: String,
    content: String,
    created_by: i32,
}

#[derive(Deserialize,Serialize, FromRow)]
struct Login {
    id_user: i32,
    username: String,
    email: String,
    password: String,
    phone_number: String,
    role: String,
}

#[derive(Deserialize)]
pub struct CreateArticleBody {
    pub title: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct CreateOtpBody {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateRegisterBody {
    pub username: String,
    pub email: String,
    pub password: String,
    pub phone_number: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct CreateLoginBody {
    pub email: String,
    pub password: String,
}








#[get("/users")]
pub async fn fetch_users(state: Data<AppState>) -> impl Responder {
    // "GET /users".to_string()
    println!("woi");
    match sqlx::query_as::<_, User>("SELECT id, first_name, last_name FROM users")
        .fetch_all(&state.db)
        .await
    {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(_) => HttpResponse::NotFound().json("No users found"),
    }
}

#[get("/users/{id}/articles")]
pub async fn fetch_user_articles(state: Data<AppState>, path: Path<i32>) -> impl Responder {
    let id: i32 = path.into_inner();
    // format!("GET /users/{id}/articles")

    match sqlx::query_as::<_, Article>(
        "SELECT id, title, content, created_by FROM articles WHERE created_by = $1"
    )
        .bind(id)
        .fetch_all(&state.db)
        .await
    {
        Ok(articles) => HttpResponse::Ok().json(articles),
        Err(_) => HttpResponse::NotFound().json("No articles found"),
    }
}

#[post("/users/{id}/articles")]
pub async fn create_user_article(state: Data<AppState>, path: Path<i32>, body: Json<CreateArticleBody>) -> impl Responder {
    println!("woi");
    let id: i32 = path.into_inner();
    // format!("POST /users/{id}/articles")

    match sqlx::query_as::<_, Article>(
        "INSERT INTO articles (title, content, created_by) VALUES ($1, $2, $3) RETURNING id, title, content, created_by"
    )
        .bind(body.title.to_string())
        .bind(body.content.to_string())
        .bind(id)
        .fetch_one(&state.db)
        .await
    {
        Ok(article) => HttpResponse::Ok().json(article),
        Err(_) => HttpResponse::InternalServerError().json("Failed to create user article"),
    }
}

#[post("/register")]
pub async fn register_user(state: Data<AppState>,  body: Json<CreateRegisterBody>) -> impl Responder {
    let hash_secret = std::env::var("HASH_SECRET").expect("HASH_SECRET must be set!");
    let mut hasher = Hasher::default();
    let hash = hasher
        .with_password(body.password.to_string())
        .with_secret_key(hash_secret)
        .hash()
        .unwrap();

    match sqlx::query_as::<_, Login>(
        "INSERT INTO table_user (username,email,password,phone_number,role) VALUES ($1,$2,$3,$4,$5)"
    )
        .bind(body.username.to_string())
        .bind(body.email.to_string())
        .bind(hash)
        .bind(body.phone_number.to_string())
        .bind(body.role.to_string())
        .fetch_all(&state.db)
        .await
    {
        Ok(_) => HttpResponse::Ok().json("Credential sudah ditambahkan"),
        Err(_) => HttpResponse::InternalServerError().json("Failed to Register user"),
    }

}
#[post("/login")]
pub async fn login_user(state: Data<AppState>,  body: Json<CreateLoginBody>) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(
        std::env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set!")
            .as_bytes(),
    ).unwrap();
    match sqlx::query_as::<_, Login> ("SELECT * from table_user WHERE email=$1")
        .bind(body.email.to_string())
        .fetch_all(&state.db)
        .await
    {
        Ok(loginx) => {
            let mut custom_respond = CustomJwt{
                jwt: String::from(""),
                status: String::from("Invalid Credentials")
            };
    
            if let Some(login) = loginx.first(){
                let hash_secret = std::env::var("HASH_SECRET").expect("HASH_SECRET must be set!");
                let mut verifier = Verifier::default();
                let is_valid = verifier
                    .with_hash(&login.password)
                    .with_password(body.password.to_string())
                    .with_secret_key(hash_secret)
                    .verify()
                    .unwrap();
                if is_valid {
                    let claims = TokenClaims{id_user: login.id_user,username: login.username.clone(), email: login.email.clone(), phone_number: login.phone_number.clone(), role: login.role.clone()};
                    let token_str = claims.sign_with_key(&jwt_secret).unwrap();
                    custom_respond.jwt = token_str;
                    custom_respond.status = String::from("jwt Obtained");
                } 
            }

            if &custom_respond.jwt != ""{
                HttpResponse::Ok().json(custom_respond)
            } else {
                HttpResponse::NotFound().json(custom_respond)
            }
            
        },
        Err(_) => HttpResponse::InternalServerError().json("Failed to Authenticate user"),
    }
}
/*#[post(/fileacces)]*/