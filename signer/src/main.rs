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
use shared::{InitResp, SignReq, SignResp, RecoverySignReq, RecoverySignResp, UnvaultSignReq, UnvaultSignResp};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
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
            .app_data(web::JsonConfig::default().limit(256 * 1024 * 1024))
            .service(session_init)
            .service(session_sign)
            .service(sign_recovery)
            .service(sign_unvault)
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
    //println!("req: {:?}", req);
    let session_id = id.to_string();

    // Delete all data about this session, ensuring we will never sign twice with same key.
    let session = match data.sessions.lock().unwrap().remove(&session_id) {
        None => return Err(ResourceNotFound.into()),
        Some(s) => s,
    };

    let seckey = session.secret_key;
    let secnonce = session.secret_nonce;

    let b = match MaybeScalar::from_hex(&req.b) {
        Ok(b) => b,
        Err(e) => return Err(JsonPayloadError::Payload(PayloadError::EncodingCorrupted).into()),
    };

    let ep = match MaybeScalar::from_hex(&req.e) {
        Ok(e) => e,
        Err(e) => return Err(JsonPayloadError::Payload(PayloadError::EncodingCorrupted).into()),
    };

    match req.tx_type.as_str() {
        "RECOVERY" => {
            // TODO: tx spends to hardcoded recovery address (committed to during init?, or at first sign)
        },
        "VAULT" => {},
        "UNVAULT" => {
            // TODO: tx spends into a new address derived from the same session pubkey, just with an added tweak (maybe the script tree is tweak enough?)
            // + a script path spending to the recovery address (must provably be only script path),
            // also committing to a final destination
        },
        "FINAL" => {
            // TODO: tx is timelocked, spends from the unvault output key and spends to final destination.
        },
        _ => {
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
    let mut child = Command::new("/Users/johan.halseth/code/rust/zk-musig/target/release/host")
        //.env("RISC0_DEV_MODE", "true")
        .arg(format!("--verify=true"))
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    child.stdin.as_mut().unwrap().write_all(req.zk_proof.as_bytes())?;

    let output = child.wait_with_output()?;

    if !output.status.success() {
        println!("zk_proof failed: {}", String::from_utf8_lossy(&output.stderr));
        return Err(ErrorInternalServerError("zk_proof failed"));
    }

    let proof = String::from_utf8(output.stdout).unwrap();
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

    let resp = SignResp {
        session_id,
        sig: sig.encode_hex(),
    };
    Ok(web::Json(resp))
}

#[post("/vault/recovery/{id}")]
async fn sign_recovery(
    data: web::Data<AppState>,
    id: web::Path<String>,
    req: web::Json<RecoverySignReq>,
) -> Result<impl Responder> {
    println!("Recovery sign request for session: {}", id);
    
    let session_id = id.to_string();
    
    // Verify that this session exists and hasn't been used yet
    let session = match data.sessions.lock().unwrap().get(&session_id) {
        None => return Err(ResourceNotFound.into()),
        Some(s) => s.clone(),
    };
    
    // Verify ZK proof that the recovery transaction is valid
    println!("Verifying ZK proof for recovery transaction...");
    let zk_verification_result = verify_zk_proof(&req.zk_proof)?;
    
    if !zk_verification_result {
        println!("ZK proof verification failed for recovery transaction");
        return Err(ErrorInternalServerError("Invalid ZK proof"));
    }
    
    // For now, return the PSBT unchanged (placeholder for actual signing)
    // In a real implementation, this would:
    // 1. Extract sighash from recovery PSBT
    // 2. Generate blind signature on the sighash
    // 3. Return signed PSBT
    
    println!("ZK proof verified - signing recovery transaction (placeholder)");
    
    let response = RecoverySignResp {
        session_id,
        signed_recovery_psbt: req.recovery_psbt.clone(),
    };
    
    Ok(web::Json(response))
}

#[post("/vault/unvault/{id}")]
async fn sign_unvault(
    data: web::Data<AppState>,
    id: web::Path<String>,
    req: web::Json<UnvaultSignReq>,
) -> Result<impl Responder> {
    println!("Unvault sign request for session: {}", id);
    
    let session_id = id.to_string();
    
    // Verify that this session exists and hasn't been used yet  
    let session = match data.sessions.lock().unwrap().get(&session_id) {
        None => return Err(ResourceNotFound.into()),
        Some(s) => s.clone(),
    };
    
    // Verify ZK proof that both unvault transactions are valid
    println!("Verifying ZK proof for unvault transactions...");
    let zk_verification_result = verify_zk_proof(&req.zk_proof)?;
    
    if !zk_verification_result {
        println!("ZK proof verification failed for unvault transactions");
        return Err(ErrorInternalServerError("Invalid ZK proof"));
    }
    
    // For now, return the PSBTs unchanged (placeholder for actual signing)
    // In a real implementation, this would:
    // 1. Extract sighashes from both PSBTs
    // 2. Generate blind signatures on both sighashes
    // 3. Return signed PSBTs
    
    println!("ZK proof verified - signing unvault transactions (placeholder)");
    
    let response = UnvaultSignResp {
        session_id,
        signed_unvault_psbt: req.unvault_psbt.clone(),
        signed_final_spend_psbt: req.final_spend_psbt.clone(),
    };
    
    Ok(web::Json(response))
}

// Helper function to verify ZK proofs
// This calls the external ZK proof verification tool
fn verify_zk_proof(zk_proof: &str) -> Result<bool> {
    println!("Verifying ZK proof with length: {}", zk_proof.len());
    
    // Call the external ZK verification tool
    let mut child = Command::new("/Users/johan.halseth/code/rust/zk-musig/target/release/host")
        .arg(format!("--verify=true"))
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| ErrorInternalServerError(format!("Failed to spawn ZK verifier: {}", e)))?;
    
    child.stdin.as_mut().unwrap().write_all(zk_proof.as_bytes())
        .map_err(|e| ErrorInternalServerError(format!("Failed to write ZK proof: {}", e)))?;
    
    let output = child.wait_with_output()
        .map_err(|e| ErrorInternalServerError(format!("ZK verifier failed: {}", e)))?;
    
    if !output.status.success() {
        println!("ZK proof verification failed: {}", String::from_utf8_lossy(&output.stderr));
        return Ok(false);
    }
    
    let proof_output = String::from_utf8(output.stdout)
        .map_err(|e| ErrorInternalServerError(format!("Invalid ZK proof output: {}", e)))?;
    println!("ZK proof verification output: {}", proof_output);
    
    Ok(true)
}
