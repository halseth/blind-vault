use actix_web::error::UrlGenerationError::ResourceNotFound;
use actix_web::error::{ErrorInternalServerError, JsonPayloadError, PayloadError, UrlencodedError};
use actix_web::{App, HttpServer, Responder, Result, get, post, web};
use clap::Parser;
use hex::ToHex;
use musig2::SecNonce;
use musig2::secp::{MaybeScalar, Scalar};
use secp256k1::{Secp256k1, SecretKey, rand};
use serde::Serialize;
use sha2::Digest;
use shared::{InitResp, SignReq, SignResp};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
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

#[get("/init/{id}")]
async fn session_init(data: web::Data<AppState>, id: web::Path<String>) -> Result<impl Responder> {
    let session_id = id.to_string();

    // Make sure session id is valid hex encoding of 32 bytes.
    match hex::decode(session_id.clone()) {
        Ok(h) => {
            if h.len() != 32 {
                return Err(UrlencodedError::Encoding.into());
            }
        }
        Err(e) => return Err(UrlencodedError::Encoding.into()),
    }

    println!("session_id: {}", session_id);

    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let pubkey = secret_key.public_key(&secp);
    let secnonce = musig2::SecNonceBuilder::new(&mut rand::rngs::OsRng)
        .with_message(&session_id)
        .build();

    let pubnonce = secnonce.public_nonce();

    let resp = InitResp {
        session_id: session_id.clone(),
        pubkey: hex::encode(pubkey.serialize()),
        pubnonce: hex::encode(pubnonce.serialize()),
    };

    let session_data = SessionData {
        session_id: session_id.clone(),
        init_resp: resp.clone(),
        secret_key: secret_key.clone(),
        secret_nonce: secnonce.clone(),
    };

    data.sessions
        .lock()
        .unwrap()
        .insert(session_id, session_data);
    Ok(web::Json(resp))
}

#[post("/sign/{id}")]
async fn session_sign(
    data: web::Data<AppState>,
    id: web::Path<String>,
    req: web::Json<SignReq>,
) -> Result<impl Responder> {
    println!("req: {:?}", req);
    let session_id = id.to_string();

    // Delete all data about this session, ensuring we will never sign twice with same key.
    let session = match data.sessions.lock().unwrap().remove(&session_id) {
        None => return Err(ResourceNotFound.into()),
        Some(s) => s,
    };

    let seckey = session.secret_key;
    let secnonce = session.secret_nonce;

    let key_coeff = Scalar::one();

    let b = match MaybeScalar::from_hex(&req.b) {
        Ok(b) => b,
        Err(e) => return Err(JsonPayloadError::Payload(PayloadError::EncodingCorrupted).into()),
    };

    let ep = match MaybeScalar::from_hex(&req.e) {
        Ok(e) => e,
        Err(e) => return Err(JsonPayloadError::Payload(PayloadError::EncodingCorrupted).into()),
    };

    let sig: MaybeScalar = match musig2::sign_partial_challenge(
        b,
        key_coeff.into(),
        req.challenge_parity.into(),
        seckey,
        secnonce,
        req.nonce_parity.into(),
        ep,
    ) {
        Ok(s) => s,
        Err(e) => {
            println!("sign partial challenge error: {:?}", e);
            return Err(ErrorInternalServerError(e))
        },
    };

    let resp = SignResp {
        session_id,
        sig: sig.encode_hex(),
    };
    Ok(web::Json(resp))
}
