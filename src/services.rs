use std::sync::{Arc, Mutex};
use crate::AppStatex;
use actix_web::{
    post,
    web::{Data, Json},
    HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{self, FromRow};


//Data Struct

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct OtpData {
    email: String,
    otp: i32,
    timestamp: i64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct OtpDataForm {
    email: String,
    otp: i32,
    timestamp: i64,
    username: String,
    phone_number: String,
    role: String,
}

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
}
#[derive(Deserialize)]
pub struct CreateOtpFormBody {
    pub username: String,
    pub email: String,
    pub phone_number: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct CreateRegisterBody {
    pub username: String,
    pub email: String,
    pub password: String,
    pub phone_number: String,
    pub role: String,
    pub otp: i32,
}

#[derive(Deserialize)]
pub struct CreateSettingsBody {
    pub username: String,
    pub email: String,
    pub new_email: String,
    pub password: String,
    pub phone_number: String,
    pub otp: i32,
}

#[derive(Deserialize)]
pub struct CreateDeleteBody {
    pub email: String,
    pub otp: i32,
}

#[derive(Deserialize)]
pub struct CreateLoginBody {
    pub email: String,
    pub password: String,
}


//Services

#[post("/register")]
pub async fn register_user(
    state: Data<AppStatex>,
    body: Json<CreateRegisterBody>,
    otp_state: Data<Arc<Mutex<Vec<OtpDataForm>>>>,
) -> impl Responder {
    match otp_state.lock() {
        Ok(x) => {
            let rethrived_otp: Vec<OtpDataForm> = x
                .iter()
                .filter(|f| *f.email == body.email )
                .cloned()
                .collect();
            let otpval = rethrived_otp.first();
            match otpval {
                Some(x) => {
                    if x.otp == body.otp && x.phone_number == body.phone_number && x.username == body.username && x.role == body.role {
                        if chrono::offset::Utc::now().timestamp() - x.timestamp < 300 {
                            let password = body.password.as_bytes();
                            let salt = SaltString::generate(&mut OsRng);

                            // Argon2 with default params (Argon2id v19)
                            let argon2 = Argon2::default();

                            // Hash password to PHC string ($argon2id$v=19$...)
                            let password_hash =
                                argon2.hash_password(password, &salt).unwrap().to_string();
                            match sqlx::query(
                        "INSERT INTO table_user (username,email,password,phone_number,role) VALUES ($1,$2,$3,$4,$5)",
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
                        } else {
                            HttpResponse::InternalServerError().json("OTP Expired, Request new OTP")
                        }
                    } else {
                        HttpResponse::NotFound().json("Invalid OTP/ Data Form")
                    }
                }
                None => HttpResponse::NotFound().json("No Registry OTP data"),
            }
        }
        Err(_) => HttpResponse::NotFound().json("No OTP dataset"),
    }
}
#[post("/login")]
pub async fn login_user(state: Data<AppStatex>, body: Json<CreateLoginBody>) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(
        std::env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set!")
            .as_bytes(),
    )
    .unwrap();

    match sqlx::query_as::<_, Login>("SELECT * from table_user WHERE email=$1")
        .bind(body.email.to_string())
        .fetch_all(&state.db)
        .await
    {
        Ok(loginx) => {
            let mut custom_respond = CustomJwt {
                jwt: String::from(""),
                status: String::from("Invalid Credentials"),
            };

            if let Some(login) = loginx.first() {
                let parsed_hash = PasswordHash::new(&login.password).unwrap();
                let verifier = Argon2::default();
                let is_valid = verifier
                    .verify_password(body.password.as_bytes(), &parsed_hash)
                    .is_ok();

                if is_valid {
                    let claims = TokenClaims {
                        id_user: login.id_user,
                        username: String::from(&login.username),
                        email: String::from(&login.email),
                        phone_number: String::from(&login.phone_number),
                        role: String::from(&login.role),
                    };
                    let token_str = claims.sign_with_key(&jwt_secret).unwrap();
                    custom_respond.jwt = token_str;
                    custom_respond.status = String::from("jwt Obtained");
                }
            }

            if &custom_respond.jwt != "" {
                HttpResponse::Ok().json(custom_respond)
            } else {
                HttpResponse::NotFound().json(custom_respond)
            }
        }
        Err(_) => HttpResponse::InternalServerError().json("Failed to Authenticate user"),
    }
}
#[post("/otpform")]
pub async fn otp_form(
    body: Json<CreateOtpFormBody>,
    otpvec: Data<Arc<Mutex<Vec<OtpDataForm>>>>,
) -> impl Responder {
    let randotp = thread_rng().gen_range(100000..1000000);
    {
        let mut vecs = otpvec.lock().unwrap();
        vecs.retain(|f| f.email != body.email);
        vecs.push(OtpDataForm {
            email: body.email.to_string(),
            otp: randotp,
            timestamp: chrono::offset::Utc::now().timestamp(),
            username: body.username.to_string(),
            phone_number: body.phone_number.to_string(),
            role:body.role.to_string(),
        });
    }
    let hr_email = std::env::var("HR_EMAIL").expect("HR_EMAIL must be set!");
    let otp_email = std::env::var("OTP_EMAIL").expect("OTP_EMAIL must be set!");
    let otp_password = std::env::var("OTP_PASSWORD").expect("OTP_PASSWORD must be set!");
    let email = Message::builder()
        .from(format!("Siber Auth<{}>", otp_email).parse().unwrap())
        .to(format!("{}", hr_email).parse().unwrap())
        .subject("OTP Registration")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "
        New user with Informational Data

        Username\t    : {}
        Email\t\t\t : {}
        Phone Number\t: {}
        Role\t\t\t  : {}


        Requesting an OTP :\t{}
        ",
            body.username, body.email, body.phone_number, body.role, randotp
        ))
        .unwrap();

    let creds = Credentials::new(otp_email.to_owned(), otp_password.to_owned());

    // Open a remote connection to gmail
    let mailer = SmtpTransport::starttls_relay("smtp-mail.outlook.com")
        .unwrap()
        .credentials(creds)
        .port(25)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => HttpResponse::Ok().json("Email sent successfully!"),
        Err(e) => HttpResponse::InternalServerError()
            .json(format!("Could not send email: {}", e.to_string())),
    }
}

#[post("/otp")]
pub async fn otp_self(
    body: Json<CreateOtpBody>,
    otpvec: Data<Arc<Mutex<Vec<OtpData>>>>,
) -> impl Responder {
    let randotp = thread_rng().gen_range(100000..1000000);
    {
        let mut vecs = otpvec.lock().unwrap();
        vecs.retain(|f| f.email != body.email);
        vecs.push(OtpData {
            email: body.email.clone(),
            otp: randotp,
            timestamp: chrono::offset::Utc::now().timestamp(),
        });
    }
    let otp_email = std::env::var("OTP_EMAIL").expect("OTP_EMAIL must be set!");
    let otp_password = std::env::var("OTP_PASSWORD").expect("OTP_PASSWORD must be set!");
    let email = Message::builder()
        .from(format!("Siber Auth<{}>", otp_email).parse().unwrap())
        .to(format!("{}", body.email).parse().unwrap())
        .subject("OTP Registration")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Your OTP for Changing Informational Data : {}",
            randotp
        ))
        .unwrap();

    let creds = Credentials::new(otp_email.to_owned(), otp_password.to_owned());

    // Open a remote connection to gmail
    let mailer = SmtpTransport::starttls_relay("smtp-mail.outlook.com")
        .unwrap()
        .credentials(creds)
        .port(25)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => HttpResponse::Ok().json("Email sent successfully!"),
        Err(e) => HttpResponse::InternalServerError()
            .json(format!("Could not send email: {}", e.to_string())),
    }
}

#[post("/settingschange")]
pub async fn change_user(
    state: Data<AppStatex>,
    body: Json<CreateSettingsBody>,
    otp_state: Data<Arc<Mutex<Vec<OtpData>>>>,
) -> impl Responder {
    match otp_state.lock() {
        Ok(x) => {
            let rethrived_otp: Vec<OtpData> = x
                .iter()
                .filter(|f| *f.email == body.email)
                .cloned()
                .collect();
            let otpval = rethrived_otp.first();
            match otpval {
                Some(x) => {
                    if x.otp == body.otp {
                        if chrono::offset::Utc::now().timestamp() - x.timestamp < 300 {
                            let mut custom_query = String::from("UPDATE table_user SET ");
                            let mut multiple = false;
                            if body.username != "" {
                                custom_query.push_str(&format!("username = '{}' ", body.username));
                                multiple = true
                            };
                            if body.new_email != "" {
                                if multiple {
                                    custom_query.push_str(", ")
                                }
                                custom_query.push_str(&format!("email = '{}' ", body.new_email));
                                multiple = true
                            };
                            if body.password != "" {
                                if multiple {
                                    custom_query.push_str(", ")
                                }
                                let password = body.password.as_bytes();
                                let salt = SaltString::generate(&mut OsRng);
                                // Argon2 with default params (Argon2id v19)
                                let argon2 = Argon2::default();
                                // Hash password to PHC string ($argon2id$v=19$...)
                                let password_hash =
                                    argon2.hash_password(password, &salt).unwrap().to_string();
                                custom_query.push_str(&format!("password = '{}' ", password_hash));
                                multiple = true
                            };
                            if body.phone_number != "" {
                                if multiple {
                                    custom_query.push_str(", ")
                                }
                                custom_query
                                    .push_str(&format!("phone_number = '{}' ", body.phone_number))
                            };
                            custom_query.push_str(&format!("WHERE email = '{}'", body.email));

                            match sqlx::query(&custom_query).fetch_all(&state.db).await {
                                Ok(_) => HttpResponse::Ok().json("Credential updated"),
                                Err(_) => HttpResponse::InternalServerError()
                                    .json("Failed to update user"),
                            }
                        } else {
                            HttpResponse::InternalServerError().json("OTP Expired, Request new OTP")
                        }
                    } else {
                        HttpResponse::NotFound().json("False OTP")
                    }
                }
                None => HttpResponse::NotFound().json("No Registry OTP data"),
            }
        }
        Err(_) => HttpResponse::NotFound().json("No OTP dataset"),
    }
}

#[post("/settingsdelete")]
pub async fn delete_user(
    state: Data<AppStatex>,
    body: Json<CreateDeleteBody>,
    otp_state: Data<Arc<Mutex<Vec<OtpData>>>>,
) -> impl Responder {
    match otp_state.lock() {
        Ok(x) => {
            let rethrived_otp: Vec<OtpData> = x
                .iter()
                .filter(|f| *f.email == body.email)
                .cloned()
                .collect();
            let otpval = rethrived_otp.first();
            match otpval {
                Some(x) => {
                    if x.otp == body.otp {
                        if chrono::offset::Utc::now().timestamp() - x.timestamp < 300 {
                            match sqlx::query("DELETE from table_user WHERE email = $1")
                                .bind(&body.email)
                                .fetch_all(&state.db)
                                .await
                            {
                                Ok(_) => HttpResponse::Ok().json("Credential deleted"),
                                Err(_) => HttpResponse::InternalServerError()
                                    .json("Failed to delete user"),
                            }
                        } else {
                            HttpResponse::InternalServerError().json("OTP Expired, Request new OTP")
                        }
                    } else {
                        HttpResponse::NotFound().json("False OTP")
                    }
                }
                None => HttpResponse::NotFound().json("No Registry OTP data"),
            }
        }
        Err(_) => HttpResponse::NotFound().json("No OTP dataset"),
    }
}
