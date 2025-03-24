use std::collections::HashMap;
use actix_web::{App, HttpServer, Responder, Result, get, web};
use secp256k1::{Secp256k1, SecretKey, rand};
use serde::Serialize;
use std::sync::Mutex;

use shared::InitResp;

// This struct represents state
struct AppState {
    app_name: String,
    counter: Mutex<i32>, // <- Mutex is necessary to mutate safely across threads
    sessions: Mutex<HashMap<String, InitResp>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_state = web::Data::new(AppState {
        app_name: String::from("Actix Web"),
        counter: Mutex::new(0),
        sessions: Mutex::new(HashMap::new()),
    });
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(session_init)
            .service(session_sign)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
    //HttpServer::new(|| {
    //    App::new()
    //        .route("/", web::get().to(hello))
    //        .route("/init", web::get().to(new_session))
    //})
    //    .bind("127.0.0.1:8080")?
    //    .run()
    //    .await
}

async fn hello() -> impl Responder {
    "Hello, world!"
}


#[get("/init/{id}")]
async fn session_init(
    data: web::Data<AppState>,
    id: web::Path<String>,
) -> Result<impl Responder> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let pubkey = secret_key.public_key(&secp);

    let secnonce = musig2::SecNonceBuilder::new(&mut rand::rngs::OsRng)
        .with_message(b"hello world!")
        .build();

    let pubnonce = secnonce.public_nonce();

    let obj = InitResp {
        id: id.to_string(),
        pubkey: hex::encode(pubkey.serialize()),
        pubnonce: hex::encode(pubnonce.serialize()),
    };

    data.sessions.lock().unwrap().insert(id.to_string(), obj.clone());
    println!("map: {:?}", data.sessions.lock().unwrap());
    Ok(web::Json(obj))
}

#[get("/sign/{name}")]
async fn session_sign(name: web::Path<String>) -> Result<impl Responder> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let pubkey = secret_key.public_key(&secp);

    let secnonce = musig2::SecNonceBuilder::new(&mut rand::rngs::OsRng)
        .with_message(b"hello world!")
        .build();

    let pubnonce = secnonce.public_nonce();

    let obj = InitResp {
        id: name.to_string(),
        pubkey: hex::encode(pubkey.serialize()),
        pubnonce: hex::encode(pubnonce.serialize()),
    };
    Ok(web::Json(obj))
}

async fn new_session() -> impl Responder {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());

    let secnonce = musig2::SecNonceBuilder::new(&mut rand::rngs::OsRng)
        .with_message(b"hello world!")
        .build();

    "new session"
}
