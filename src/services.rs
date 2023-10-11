use crate::AppStatex;
use actix_web::{
    post,
    web::{Data, Json},
    HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hmac::{Hmac, Mac};
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
struct CustomJwt {
    jwt: String,
    status: String,
}

#[derive(Deserialize, Serialize, FromRow)]
struct Login {
    id_user: i32,
    username: String,
    email: String,
    password: String,
    phone_number: String,
    role: String,
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

#[post("/register")]
pub async fn register_user(
    state: Data<AppStatex>,
    body: Json<CreateRegisterBody>,
) -> impl Responder {
    let password = body.password.as_bytes(); 
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(password, &salt).unwrap().to_string();
    match sqlx::query_as::<_, Login>(
        "INSERT INTO table_user (username,email,password,phone_number,role) VALUES ($1,$2,$3,$4,$5)"
    )
        .bind(body.username.to_string())
        .bind(body.email.to_string())
        .bind(password_hash)
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
pub async fn login_user(state: Data<AppStatex>, body: Json<CreateLoginBody>) -> impl Responder {
    
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
                let parsed_hash = PasswordHash::new(&login.password).unwrap();
                let verifier = Argon2::default();
                let is_valid = verifier
                .verify_password(body.password.as_bytes(), &parsed_hash).is_ok();
                    
                if is_valid {
                    let claims = TokenClaims{id_user: login.id_user,username: String::from(&login.username), email: String::from(&login.email), phone_number: String::from(&login.phone_number), role: String::from(&login.role)};
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
