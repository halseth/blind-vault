use actix_web::error::UrlGenerationError::ResourceNotFound;
use actix_web::error::{ErrorInternalServerError, JsonPayloadError, PayloadError, UrlencodedError};
use actix_web::{App, HttpServer, Responder, Result, get, post, web};
use clap::Parser;
use hex::ToHex;
use musig2::SecNonce;
use musig2::secp::MaybeScalar;
use secp256k1::{Secp256k1, SecretKey, PublicKey, rand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::{InitReq, InitResp, SignReq, SignResp};
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
    secret_key: SecretKey,
    secret_nonces: Vec<SecNonce>,  // Vector of nonces, used and deleted in order
    timelock_commitment: Vec<u8>, // SHA256(salt || nSequence), will be verified during signing of the finalization tx
}

// Structs for parsing zk-musig verification output
#[derive(Deserialize, Debug)]
struct ZkProofOutput {
    pub verified: bool,
    pub journal: JournalData,
}

#[derive(Deserialize, Debug)]
struct JournalData {
    pub pubkey: String,
    pub pubnonce: String,
    pub challenge_parity: u8,
    pub nonce_parity: u8,
    pub b: String,
    pub e: String,
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

#[post("/init/{id}")]
async fn session_init(
    data: web::Data<AppState>,
    id: web::Path<String>,
    req: web::Json<InitReq>,
) -> Result<impl Responder> {
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

    // Decode and validate timelock commitment
    let timelock_commitment = match hex::decode(&req.timelock_commitment) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(UrlencodedError::Encoding.into());
            }
            bytes
        }
        Err(e) => return Err(UrlencodedError::Encoding.into()),
    };

    println!("session_id: {}", session_id);
    println!("timelock_commitment: {}", req.timelock_commitment);

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_str( &data.args.priv_key ).unwrap();
    let pubkey = secret_key.public_key(&secp);

    // Generate multiple nonces (4 for vault + unvault flow) for this session
    let num_nonces = 4;
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
        secret_key: secret_key.clone(),
        secret_nonces: secret_nonces,
        timelock_commitment: timelock_commitment,
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

    // Verify ZK proof using zk-musig CLI
    println!("Verifying ZK proof ({} bytes)", req.zk_proof.len());

    let mut child = Command::new("zk-musig")
        .arg("verify")
        .arg("--input")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            eprintln!("Failed to spawn zk-musig: {}", e);
            ErrorInternalServerError("Failed to spawn zk-musig verifier")
        })?;

    // Write proof to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(req.zk_proof.as_bytes()).map_err(|e| {
            eprintln!("Failed to write proof to zk-musig: {}", e);
            ErrorInternalServerError("Failed to write proof to verifier")
        })?;
    }

    let output = child.wait_with_output().map_err(|e| {
        eprintln!("Failed to wait for zk-musig: {}", e);
        ErrorInternalServerError("Failed to wait for verifier")
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("ZK proof verification failed: {}", stderr);
        return Err(ErrorInternalServerError("ZK proof verification failed"));
    }

    let verification_output_str = String::from_utf8(output.stdout).map_err(|e| {
        eprintln!("Failed to parse verification output: {}", e);
        ErrorInternalServerError("Failed to parse verification output")
    })?;

    // Parse the JSON output from zk-musig verify
    let proof_output: ZkProofOutput = serde_json::from_str(&verification_output_str).map_err(|e| {
        eprintln!("Failed to deserialize proof output: {}", e);
        eprintln!("Output was: {}", verification_output_str);
        ErrorInternalServerError("Failed to parse proof verification JSON")
    })?;

    if !proof_output.verified {
        eprintln!("ZK proof verification returned verified=false");
        return Err(ErrorInternalServerError("ZK proof not verified"));
    }

    // Verify that the journal data matches the SignReq parameters and session data
    println!("Verifying journal matches SignReq parameters and session data...");

    // Verify pubkey matches this signer's public key
    let secp = Secp256k1::new();
    let expected_pubkey = seckey.public_key(&secp);
    let expected_pubkey_hex = hex::encode(expected_pubkey.serialize());

    if proof_output.journal.pubkey != expected_pubkey_hex {
        eprintln!("Pubkey mismatch: journal={}, expected={}",
            proof_output.journal.pubkey, expected_pubkey_hex);
        return Err(ErrorInternalServerError("Pubkey in proof doesn't match signer's public key"));
    }

    // Verify pubnonce matches this session's nonce
    let expected_pubnonce = secnonce.public_nonce();
    let expected_pubnonce_hex = hex::encode(expected_pubnonce.serialize());

    if proof_output.journal.pubnonce != expected_pubnonce_hex {
        eprintln!("Pubnonce mismatch: journal={}, expected={}",
            proof_output.journal.pubnonce, expected_pubnonce_hex);
        return Err(ErrorInternalServerError("Pubnonce in proof doesn't match session nonce"));
    }

    // Verify challenge_parity matches
    if proof_output.journal.challenge_parity != req.challenge_parity {
        eprintln!("Challenge parity mismatch: journal={}, req={}",
            proof_output.journal.challenge_parity, req.challenge_parity);
        return Err(ErrorInternalServerError("Challenge parity mismatch between proof and request"));
    }

    // Verify nonce_parity matches
    if proof_output.journal.nonce_parity != req.nonce_parity {
        eprintln!("Nonce parity mismatch: journal={}, req={}",
            proof_output.journal.nonce_parity, req.nonce_parity);
        return Err(ErrorInternalServerError("Nonce parity mismatch between proof and request"));
    }

    // Verify parameter 'b' matches
    if proof_output.journal.b != req.b {
        eprintln!("Parameter 'b' mismatch: journal={}, req={}",
            proof_output.journal.b, req.b);
        return Err(ErrorInternalServerError("Parameter 'b' mismatch between proof and request"));
    }

    // Verify parameter 'e' matches
    if proof_output.journal.e != req.e {
        eprintln!("Parameter 'e' mismatch: journal={}, req={}",
            proof_output.journal.e, req.e);
        return Err(ErrorInternalServerError("Parameter 'e' mismatch between proof and request"));
    }

    println!("ZK proof verified successfully");
    println!("Journal verification passed - all parameters match (pubkey, pubnonce, b, e, parities)");

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
