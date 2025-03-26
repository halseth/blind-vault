use actix_web::{App, HttpServer, Responder, Result, get, post, web};
use clap::Parser;
use hex::ToHex;
use musig2::secp::MaybeScalar;
use musig2::{PubNonce, SecNonce};
use secp256k1::{PublicKey, Secp256k1, SecretKey, rand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::{InitResp, SignReq, SignResp};
use std::collections::HashMap;
use std::net;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Mutex;

// This struct represents state
struct AppState {
    sessions: Mutex<HashMap<String, SessionData>>,
}

#[derive(Clone, Debug)]
struct SessionData {
    session_id: String,
    init_resp: InitResp,
    secret_key: SecretKey,
    secret_nonce: SecNonce,
}

#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Args {
    #[arg(long)]
    listen: SocketAddr,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let bind = args.listen;
    println!("listening on {}", bind);

    let app_state = web::Data::new(AppState {
        sessions: Mutex::new(HashMap::new()),
    });
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(session_init)
            .service(session_sign)
    })
    .bind(bind)?
    .run()
    .await
}

async fn hello() -> impl Responder {
    "Hello, world!"
}

#[get("/init/{id}")]
async fn session_init(data: web::Data<AppState>, id: web::Path<String>) -> Result<impl Responder> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let pubkey = secret_key.public_key(&secp);

    let secnonce = musig2::SecNonceBuilder::new(&mut rand::rngs::OsRng)
        .with_message(&id.to_string())
        .build();

    let pubnonce = secnonce.public_nonce();

    let resp = InitResp {
        session_id: id.to_string(),
        pubkey: hex::encode(pubkey.serialize()),
        pubnonce: hex::encode(pubnonce.serialize()),
    };

    let session_data = SessionData {
        session_id: id.to_string(),
        init_resp: resp.clone(),
        secret_key: secret_key.clone(),
        secret_nonce: secnonce,
    };

    data.sessions
        .lock()
        .unwrap()
        .insert(id.to_string(), session_data);
    println!("map: {:?}", data.sessions.lock().unwrap());
    Ok(web::Json(resp))
}

#[post("/sign/{id}")]
async fn session_sign(
    data: web::Data<AppState>,
    id: web::Path<String>,
    req: web::Json<SignReq>,
) -> Result<impl Responder> {
    println!("req: {:?}", req);

    let session = data
        .sessions
        .lock()
        .unwrap()
        .remove(&id.to_string())
        .unwrap();

    let seckey = session.secret_key;
    let secnonce = session.secret_nonce;

    let key_coeff = MaybeScalar::from_hex(&req.key_coeff).unwrap();
    let ep = MaybeScalar::from_hex(&req.e).unwrap();

    let sig: MaybeScalar = musig2::sign_partial_challenge(
        key_coeff,
        req.key_parity.into(),
        seckey,
        secnonce,
        req.nonce_parity.into(),
        ep,
    )
    .expect("error creating partial signature");

    let resp = SignResp {
        sig: sig.encode_hex(),
    };
    Ok(web::Json(resp))
}
