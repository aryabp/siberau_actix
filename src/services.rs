use crate::{AppStatex, Role};
use actix_web::{
    get, post,
    web::{Data, Json},
    HttpResponse, Responder,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use lettre::message::{header::ContentType, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use sqlx::{self, FromRow};
use std::sync::{Arc, Mutex};

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
    role: Role,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub id_user: i32,
    pub username: String,
    pub email: String,
    pub phone_number: String,
    pub role: Role,
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
    pub role: Role,
}

#[derive(Deserialize)]
pub struct CreateRegisterBody {
    pub username: String,
    pub email: String,
    pub password: String,
    pub phone_number: String,
    pub role: Role,
    pub otp: String,
}

#[derive(Deserialize)]
pub struct CreateSettingsBody {
    pub username: String,
    pub email: String,
    pub new_email: String,
    pub password: String,
    pub phone_number: String,
    pub otp: String,
}

#[derive(Deserialize)]
pub struct CreateDeleteBody {
    pub email: String,
    pub otp: String,
}

#[derive(Deserialize)]
pub struct CreateLoginBody {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateGetAccessBody {
    pub jwt: String,
}

#[derive(Deserialize)]
pub struct CreateAccessBody {
    pub jwt: String,
    pub id_access: i32,
}

#[derive(Deserialize)]
pub struct CreateReqAccessBody {
    pub jwt: String,
    pub req_filename: String,
    pub req_path: String,
}

#[derive(Deserialize, Serialize, FromRow)]
struct Access {
    id_access: i32,
    filename: String,
    path: String,
    requester: String,
    owner: String,
    is_enable: bool,
}
//Services

#[get("/permissions")]
pub async fn permissions() -> impl Responder {
    HttpResponse::Ok()
        .content_type(actix_web::http::header::ContentType::html())
        .body(format!(
            "<!DOCTYPE html>
    <html lang=\"en\">
    <head>
        <meta charset=\"UTF-8\">
        <title>Permissions</title>
    </head>
    <body>
        <h1>Permissions</h1>
        <script>window.location.replace('http://tauri.localhost')</script>
    </body>
    </html>"
        ))
}

#[get("/listrole")]
pub async fn list_role() -> impl Responder {
    let roles = vec![
        Role::Kasatsiber,
        Role::Kasiops,
        Role::KatimCegah,
        Role::KatimTanggul,
        Role::KatimTindak,
        Role::KatimPulih,
        Role::StaffCegah,
        Role::StaffTanggul,
        Role::StaffTindak,
        Role::StaffPulih,
    ];
    HttpResponse::Ok().json(serde_json::json!(&roles))
}

#[post("/register")]
pub async fn register_user(
    state: Data<AppStatex>,
    body: Json<CreateRegisterBody>,
    otp_state: Data<Arc<Mutex<Vec<OtpDataForm>>>>,
) -> impl Responder {
    let mut convert_otp: i32 = 0;
    match body.otp.parse::<i32>() {
        Ok(x) => convert_otp = x,
        Err(_) => eprintln!(" Invalid Type"),
    }
    match otp_state.lock() {
        Ok(x) => {
            let rethrived_otp: Vec<OtpDataForm> = x
                .iter()
                .filter(|f| *f.email == body.email)
                .cloned()
                .collect();
            let otpval = rethrived_otp.first();
            match otpval {
                Some(x) => {
                    if x.otp == convert_otp
                        && x.phone_number == body.phone_number
                        && x.username == body.username
                        && x.role == body.role
                    {
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
                        Err(x) => {println!("{}",x);
                            HttpResponse::InternalServerError().json("Failed to Register user")},
                    }
                        } else {
                            HttpResponse::BadRequest().json("OTP Expired, Request new OTP")
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
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };
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
                        role: Role::from_string(&login.role).unwrap(),
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
            role: body.role.clone(),
        });
    }
    let hr_email = std::env::var("HR_EMAIL").expect("HR_EMAIL must be set!");
    let otp_email = std::env::var("OTP_EMAIL").expect("OTP_EMAIL must be set!");
    let otp_password = std::env::var("OTP_PASSWORD").expect("OTP_PASSWORD must be set!");

    let format_plain = format!(
        "
    User Register Informational Data

    Username\t    : {}
    Email\t\t\t : {}
    Phone Number\t: {}
    Role\t\t\t  : {}


    Requesting an OTP :\t{}
    ",
        body.username, body.email, body.phone_number, body.role, randotp
    );

    let format_html = format!( "<!DOCTYPE html>
    <html lang=\"en\">
    <head>
        <meta charset=\"UTF-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
        <title>Siber authentication</title>
    </head>
    <body>
        <div style=\" align-items: center;\">
            <h4 style=\"font-family: Arial, Helvetica, sans-serif;\">User Register Informational Data</h4>
            <p>Username : {}</p>
            <p>Email : {}</p>
            <p>Phone Number : {}</p>
            <p>Role : {}</p></br>
            <p>Requesting an OTP : {}</p>
        </div>
    </body>
    </html>",body.username, body.email, body.phone_number, body.role, randotp);
    let email = Message::builder()
        .from(format!("Siber Auth<{}>", otp_email).parse().unwrap())
        .to(format!("{}", hr_email).parse().unwrap())
        .subject("OTP Registration")
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(format_plain),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(format_html),
                ),
        )
        .expect("failed to build email");

    let creds = Credentials::new(otp_email.to_owned(), otp_password.to_owned());

    // Open a remote connection to gmail
    let mailer = SmtpTransport::starttls_relay("smtp-mail.outlook.com")
        .unwrap()
        .credentials(creds)
        .port(587)
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
    let format_plain = format!("Your OTP for Changing Informational Data : {}", randotp);

    let format_html = format!( "<!DOCTYPE html>
    <html lang=\"en\">
    <head>
        <meta charset=\"UTF-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
        <title>Siber authentication</title>
    </head>
    <body>
        <div style=\" align-items: center;\">
            <h4 style=\"font-family: Arial, Helvetica, sans-serif;\">Your OTP for Changing Informational Data</h4>
            <h2>{}</h2>
        </div>
    </body>
    </html>",randotp);
    let otp_email = std::env::var("OTP_EMAIL").expect("OTP_EMAIL must be set!");
    let otp_password = std::env::var("OTP_PASSWORD").expect("OTP_PASSWORD must be set!");
    let email = Message::builder()
        .from(format!("Siber Auth<{}>", otp_email).parse().unwrap())
        .to(format!("{}", body.email).parse().unwrap())
        .subject("OTP Registration")
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(format_plain),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(format_html),
                ),
        )
        .unwrap();

    let creds = Credentials::new(otp_email.to_owned(), otp_password.to_owned());

    // Open a remote connection to gmail
    let mailer = SmtpTransport::starttls_relay("smtp-mail.outlook.com")
        .unwrap()
        .credentials(creds)
        .port(587)
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
    let mut convert_otp: i32 = 0;
    match body.otp.parse::<i32>() {
        Ok(x) => convert_otp = x,
        Err(_) => eprintln!(" Invalid Type"),
    }
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
                    if x.otp == convert_otp {
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
    let mut convert_otp: i32 = 0;
    match body.otp.parse::<i32>() {
        Ok(x) => convert_otp = x,
        Err(_) => eprintln!(" Invalid Type"),
    }
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
                    if x.otp == convert_otp {
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

#[post("/getaccesslist")]
pub async fn get_accesslist(
    state: Data<AppStatex>,
    body: Json<CreateGetAccessBody>,
) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };

    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claim: TokenClaims = fe;
            //let drop_bentar   = claim.id_user as i64;
            
            match sqlx::query_as::<_, Access>(
                "SELECT id_access, filename , path , owner , username AS requester , is_enable from table_access AS ta INNER JOIN table_user AS tu ON ta.requester = tu.id_user WHERE owner = $1  OR requester = $2 ",
            )
            .bind(claim.role.to_string())
            .bind(claim.id_user)
            .fetch_all(&state.db)
            .await
            {
                Ok(access_li) => HttpResponse::Ok().json(json!(access_li)),
                Err(er) => HttpResponse::InternalServerError().json(er.to_string()),
            }
        }
        Err(_) => HttpResponse::BadRequest().json("Access denied"),
    }
}

#[post("/deleteaccess")]
pub async fn delete_access(state: Data<AppStatex>, body: Json<CreateAccessBody>) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };

    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claim: TokenClaims = fe;
            match sqlx::query("DELETE from table_access WHERE id_access = $1 AND ( owner = $2 OR requester = $3 ) ")
                .bind(&body.id_access)
                .bind(claim.role.to_string())
                .bind(claim.id_user)
                .fetch_all(&state.db)
                .await
            {
                Ok(_) => HttpResponse::Ok().json("Access deleted"),
                Err(_) => HttpResponse::InternalServerError().json("Failed to delete Access"),
            }
        }
        Err(_) => HttpResponse::BadRequest().json("Access denied"),
    }
}

#[post("/enableaccess")]
pub async fn enable_access(state: Data<AppStatex>, body: Json<CreateAccessBody>) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };

    match body.jwt.verify_with_key(&jwt_secret) {
        Ok(fe) => {
            let claim: TokenClaims = fe;
            match sqlx::query(
                "UPDATE table_access SET is_enable = NOT is_enable WHERE id_access = $1 AND owner = $2",
            )
            .bind(&body.id_access)
            .bind(claim.role.to_string())
            .fetch_all(&state.db)
            .await
            {
                Ok(_) => HttpResponse::Ok().json("Access changed"),
                Err(_) => HttpResponse::InternalServerError().json("Failed to change access"),
            }
        }
        Err(_) => HttpResponse::BadRequest().json("Access denied"),
    }
}

#[post("/requestaccess")]
pub async fn request_access(state: Data<AppStatex>, body: Json<CreateReqAccessBody>) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = match std::env::var("JWT_SECRET") {
        Ok(secret) => Hmac::new_from_slice(secret.as_bytes()).expect("Invalid secret format!"),
        Err(_) => panic!("JWT_SECRET environment variable must be set!"),
    };
    let mut owner = String::from("Invalid dir");
    match &body.req_path.find(&{std::env::var("CEGAH_DIRECTORY").expect("SET directory a")}) {
        Some(_) => owner =  "KatimCegah".to_string(),
        None => ()
    };
    match &body.req_path.find(&{std::env::var("ALT_CEGAH_DIRECTORY").expect("SET directory a")}) {
        Some(_) => owner =  "KatimCegah".to_string(),
        None => ()
    };
    match &body.req_path.find(&{std::env::var("TANGGUL_DIRECTORY").expect("SET directory a")}) {
        Some(_) => owner =  "KatimTanggul".to_string(),
        None => ()
    };
    match &body.req_path.find(&{std::env::var("ALT_TANGGUL_DIRECTORY").expect("SET directory a")}) {
        Some(_) => owner =  "KatimTanggul".to_string(),
        None => ()
    };
    match &body.req_path.find(&{std::env::var("TINDAK_DIRECTORY").expect("SET directory a")}) {
        Some(_) => owner =  "KatimTindak".to_string(),
        None => ()
    };
    match &body.req_path.find(&{std::env::var("ALT_TINDAK_DIRECTORY").expect("SET directory a")}) {
        Some(_) => owner =  "KatimTindak".to_string(),
        None => ()
    };
    match &body.req_path.find(&{std::env::var("PULIH_DIRECTORY").expect("SET directory a")}) {
        Some(_) => owner =  "KatimPulih".to_string(),
        None => ()
    };
    match &body.req_path.find(&{std::env::var("ALT_PULIH_DIRECTORY").expect("SET directory a")}) {
        Some(_) => owner =  "KatimPulih".to_string(),
        None => ()
    };
    if owner == "Invalid dir" {
        HttpResponse::BadRequest().json(owner)
    } else {
        match body.jwt.verify_with_key(&jwt_secret) {
            Ok(fe) => {
                let claim: TokenClaims = fe;
                match sqlx::query(
                    "INSERT INTO table_access (filename,path,requester,owner,is_enable) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(&body.req_filename)
                .bind(&body.req_path)
                .bind(claim.id_user)
                .bind(owner)
                .bind(false)
                .fetch_all(&state.db)
                .await
                {
                    Ok(_) => HttpResponse::Ok().json("Access changed"),
                    Err(_) => HttpResponse::InternalServerError().json("Failed to change access"),
                }
            }
            Err(_) => HttpResponse::BadRequest().json("Access denied"),
        }
    }
}
