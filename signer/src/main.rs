use actix_web::error::UrlGenerationError::ResourceNotFound;
use actix_web::error::{ErrorInternalServerError, JsonPayloadError, PayloadError, UrlencodedError};
use actix_web::{App, HttpServer, Responder, Result, get, post, web};
use clap::Parser;
use hex::ToHex;
use musig2::SecNonce;
use musig2::secp::{MaybeScalar, Scalar};
use secp256k1::{Secp256k1, SecretKey, PublicKey, rand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use shared::{InitResp, SignReq, SignResp};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Mutex;

// This struct represents state
struct AppState {
    sessions: Mutex<HashMap<String, SessionData>>,
    args: Args,
}

#[derive(Clone, Debug)]
struct SessionData {
    session_id: String,
    init_resp: InitResp,
    secret_key: SecretKey,
    secret_nonces: Vec<SecNonce>,  // Vector of nonces, used and deleted in order
    recovery_addr: Option<String>,  // Committed recovery address
    used_for_tx_type: Option<String>, // Track what transaction type this session was used for
}

#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Args {
    #[arg(long)]
    listen: SocketAddr,

    #[arg(long)]
    priv_key: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let bind = args.listen;
    println!("listening on {}", bind);

    let app_state = web::Data::new(AppState {
        sessions: Mutex::new(HashMap::new()),
        args: args,
    });
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(web::JsonConfig::default().limit(256 * 1024 * 1024))
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
    let secret_key = SecretKey::from_str( &data.args.priv_key ).unwrap();
    let pubkey = secret_key.public_key(&secp);

    // Generate multiple nonces (2 for now) for this session
    let num_nonces = 2;
    let mut secret_nonces = Vec::new();
    let mut pubnonces = Vec::new();

    for i in 0..num_nonces {
        // Create a unique message for each nonce by appending the index
        let nonce_message = format!("{}:{}", session_id, i);
        let secnonce = musig2::SecNonceBuilder::new(&mut rand::rngs::OsRng)
            .with_message(&nonce_message)
            .build();
        let pubnonce = secnonce.public_nonce();

        secret_nonces.push(secnonce);
        pubnonces.push(hex::encode(pubnonce.serialize()));
    }

    let resp = InitResp {
        session_id: session_id.clone(),
        pubkey: hex::encode(pubkey.serialize()),
        pubnonces: pubnonces,
    };

    let session_data = SessionData {
        session_id: session_id.clone(),
        init_resp: resp.clone(),
        secret_key: secret_key.clone(),
        secret_nonces: secret_nonces,
        recovery_addr: None,
        used_for_tx_type: None,
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
    //println!("req: {:?}", req);
    let session_id = id.to_string();

    // Get the next available nonce from the session
    let (seckey, secnonce) = {
        let mut sessions = data.sessions.lock().unwrap();
        let session = match sessions.get_mut(&session_id) {
            None => return Err(ResourceNotFound.into()),
            Some(s) => s,
        };

        if session.secret_nonces.is_empty() {
            return Err(ErrorInternalServerError("No nonces available for this session"));
        }

        // Pop the first nonce from the vector (use and delete it)
        let secnonce = session.secret_nonces.remove(0);
        let seckey = session.secret_key.clone();

        // If no more nonces remain, we'll remove the session after signing
        (seckey, secnonce)
    };

    let b = match MaybeScalar::from_hex(&req.b) {
        Ok(b) => b,
        Err(e) => return Err(JsonPayloadError::Payload(PayloadError::EncodingCorrupted).into()),
    };

    let ep = match MaybeScalar::from_hex(&req.e) {
        Ok(e) => e,
        Err(e) => return Err(JsonPayloadError::Payload(PayloadError::EncodingCorrupted).into()),
    };

    // Handle different transaction types
    match req.tx_type.as_str() {
        "VAULT" => {
            println!("Processing VAULT transaction");
            // Vault transactions are the initial deposit into the aggregated key
            // Here we sign a recovery transaction spending from an input we are part of.
        },
        "RECOVERY" => {
            println!("Processing RECOVERY transaction");
            // Recovery transactions spend to a committed recovery address
        },
        "UNVAULT" => {
            println!("Processing UNVAULT transaction");
            // Unvault transactions must derive a new key with proper script paths

            // Derive the unvault public key with script tree tweak
            let unvault_pubkey = derive_unvault_pubkey(&seckey)?;
            println!("Derived unvault pubkey: {}", hex::encode(unvault_pubkey.serialize()));

            // Here we validate and sign three transactions:
            // 1) Unvault transaction spending to a new output with the same quorum
            // 2) Recovery transaction spending from the unvault transaction output back to the same recovery address
            // 3) Final timelocked transaction spending from the unvault transaction output
        },
        "FINAL" => {
            println!("Processing FINAL transaction");
            // Final timelocked spend transaction
        },
       t => {
           println!("type {} not found", t);
            return Err(JsonPayloadError::Payload(PayloadError::EncodingCorrupted).into());
        },
    }

    // TODO: need two proofs:
    // 1) verify that the musig is created correctly (zk-musig)
    // 2a) check that the recovery transaction one is signing is correct
    //  zk-tx:
    //  - spends all funds into hardcoded recovery address (1-in-1-out)
    // 2b) check that the unvault transaction one is signing is correct
    //  zk-tx:
    //  - spends all funds into aggeregate pubkey that is derived from the same pubkeys that the deposit went to. (can use exact same pubkey for now? or just tweak it).
    //  - check that it has a timelocked script path spending to the recovery addr
    // 2c) check that the spend from the unvault is correct
    //  zk-tx:
    //  - spends all funds into a pre-determined address


    println!("zk_proof: {}",  req.zk_proof.len());
    // TODO: Replace with actual ZK proof verification when available
    // let mut child = Command::new("/Users/johan.halseth/code/rust/zk-musig/target/release/host")
    //     //.env("RISC0_DEV_MODE", "true")
    //     .arg(format!("--verify=true"))
    //     .stdin(Stdio::piped())
    //     .spawn()
    //     .unwrap();
    //
    // child.stdin.as_mut().unwrap().write_all(req.zk_proof.as_bytes())?;
    //
    // let output = child.wait_with_output()?;
    //
    // if !output.status.success() {
    //     println!("zk_proof failed: {}", String::from_utf8_lossy(&output.stderr));
    //     return Err(ErrorInternalServerError("zk_proof failed"));
    // }
    //
    // let proof = String::from_utf8(output.stdout).unwrap();
    let proof = "dummy_verification_result".to_string();
    //let proof = proof.strip_suffix("\n").unwrap();
    println!("output: {}", proof);

    let sig: MaybeScalar = match musig2::sign_partial_challenge(
        b,
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

    // Clean up session if no more nonces remain
    {
        let mut sessions = data.sessions.lock().unwrap();
        if let Some(session) = sessions.get(&session_id) {
            if session.secret_nonces.is_empty() {
                println!("Removing session {} - no nonces remaining", session_id);
                sessions.remove(&session_id);
            }
        }
    }

    let resp = SignResp {
        session_id,
        sig: sig.encode_hex(),
    };
    Ok(web::Json(resp))
}

// Helper function to derive unvault public key from session key
fn derive_unvault_pubkey(secret_key: &SecretKey) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    
    // Create a tweak for the unvault key derivation
    // This could be based on script tree commitments or other vault-specific data
    let tweak_bytes = Sha256::new()
        .chain_update(b"UNVAULT_KEY_DERIVATION")
        .chain_update(secret_key.secret_bytes())
        .finalize();
    
    // Create the base public key
    let base_pubkey = secret_key.public_key(&secp);
    
    // For now, return the base pubkey (in production, this would apply proper tweaking)
    // TODO: Apply proper taproot tweaking with script tree commitments
    Ok(base_pubkey)
}
