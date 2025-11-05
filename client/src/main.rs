use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, Responder, Result, post, web};
use bitcoin::address::script_pubkey::ScriptBufExt;
use bitcoin::consensus_validation::TransactionExt;
use bitcoin::psbt::Input;
use bitcoin::secp256k1::{All, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{
    Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness, absolute, consensus, taproot, transaction,
};
use clap::Parser;
use hex::ToHex;
use musig2::secp::{G, MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AggNonce, KeyAggContext, PartialSignature, PubNonce, compute_challenge_hash_tweak,
    verify_partial_challenge,
};
use rand::Rng;
use secp256k1::{PublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::{
    InitResp, SignReq, SignResp, VaultDepositReq, VaultDepositResp, VaultSessionData,
    VaultUnvaultReq, VaultUnvaultResp,
};
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::io::Write;
use std::str::FromStr;

#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Args {
    #[arg(long)]
    cfg: Option<String>,

    #[arg(long)]
    listen: SocketAddr,

    /// Network to use.
    #[arg(long, default_value_t = Network::Signet)]
    network: Network,

    // subtract static fee. TODO: use anchor instead?
    #[arg(long)]
    static_fee: Amount,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Config {
    pub signers: Vec<String>,
}

// This struct represents state
struct AppState {
    cfg: Config,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Params {
    pub coeff_salt: String,
    pub blinding_factors: Vec<(String, String, String)>,
    pub pubkeys: Vec<String>,
    pub pubnonces: Vec<String>,
    pub message: String,
    pub signer_index: usize,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let cfg: Config = serde_json::from_str(&args.cfg.unwrap()).unwrap();
    println!("config: {:?}", cfg);

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let bind = args.listen;
    println!("listening on {}", bind);

    let app_state = web::Data::new(AppState {
        cfg: cfg,
    });
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_state.clone())
            .service(sign_vault)
            .service(sign_unvault)
    })
    .bind(bind)?
    .run()
    .await
}

#[post("/vault")]
async fn sign_vault(
    data: web::Data<AppState>,
    req: web::Json<VaultDepositReq>,
) -> actix_web::Result<impl Responder> {
    println!("Vault deposit request: {:?}", req);

    let secp = Secp256k1::new();

    let cfg = data.cfg.clone();
    let args = Args::parse();

    let sessions = init_signer_sessions(&cfg).await?;
    let num_signers = sessions.len();

    let coeff_salt = gen_coeff_salt();

    let (pubkeys, public_nonces, key_agg_ctx, aggregated_nonce) =
        aggregate_pubs(&sessions, Some(&coeff_salt), 0);

    let untweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey_untweaked();
    println!("untweaked agg pubkey X: {}", untweaked_aggregated_pubkey);
    let tweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

    let pk = bitcoin::secp256k1::PublicKey::from_slice(&untweaked_aggregated_pubkey.serialize())
        .unwrap();
    let (xonly, _) = pk.x_only_public_key();
    println!("agg pubkey: {} x-only:{}", pk, xonly);

    let tap = Address::p2tr(&secp, xonly, None, args.network);
    let sp = tap.script_pubkey();

    let mut deposit_psbt = req.deposit_psbt.clone();
    if let Some(output) = deposit_psbt.unsigned_tx.output.get_mut(0) {
        output.script_pubkey = sp.clone();
    }

    println!("deposit: {:?}", deposit_psbt);

    let body_json = serde_json::to_string(&deposit_psbt).unwrap();
    println!("body_json: {}", body_json);

    // Create transaction that spends from this output (into the fallback address).
    // Future: add some sort of miniscript config for the spending transaction?
    let utxos: Vec<TxOut> = deposit_psbt.unsigned_tx.output.to_vec();

    println!(
        "deposit transaction Details: {:#?}",
        deposit_psbt.unsigned_tx
    );

    let deposit_tx = deposit_psbt.unsigned_tx.clone();
    let txid = deposit_tx.compute_txid();
    let op = OutPoint::from_str(format!("{}:0", txid).as_str()).unwrap();

    let recovery_script_pubkey = Address::from_str(&req.recovery_addr)
        .unwrap()
        .require_network(args.network)
        .unwrap()
        .script_pubkey();

    println!(
        "prevout: {}",
        hex::encode(consensus::encode::serialize(&utxos[0]))
    );

    // Create vault recovery transaction using helper
    let recovery_tx = create_vault_recovery_transaction(
        op,
        utxos[0].value,
        recovery_script_pubkey.clone(),
        args.static_fee,
    );

    let mut recovery_psbt =
        Psbt::from_unsigned_tx(recovery_tx.clone()).expect("Could not create PSBT");
    recovery_psbt.inputs = vec![Input {
        witness_utxo: Some(utxos[0].clone()),
        ..Default::default()
    }];

    // Sign the vault recovery PSBT (uses nonce 0)
    let vault_recovery_psbt = sign_psbt(
        recovery_psbt,
        sessions.clone(),
        &key_agg_ctx,
        tweaked_aggregated_pubkey,
        &pubkeys,
        &public_nonces,
        &coeff_salt,
        "VAULT",
    )
    .await?;

    let vault_recovery_tx = vault_recovery_psbt.clone().extract_tx().unwrap();

    let serialized_vault_recovery = consensus::encode::serialize_hex(&vault_recovery_tx);
    let serialized_deposit = consensus::encode::serialize_hex(&deposit_tx);
    println!("Vault Recovery Transaction Details: {:#?}", vault_recovery_tx);
    println!("Raw deposit Transaction: {}", serialized_deposit);
    println!("Raw vault recovery Transaction: {}", serialized_vault_recovery);

    let res = vault_recovery_tx
        .verify(|op| {
            println!("fetching op {}", op);
            Some(utxos[0].clone())
        })
        .unwrap();
    println!("Vault Recovery Transaction Result: {:#?}", res);

    // Create deterministic unvault transaction to predict txid
    let unvault_tx_template = create_unvault_transaction(
        op,              // vault outpoint
        utxos[0].value,  // vault amount
        sp.clone(),      // vault scriptpubkey (same key for unvault)
        args.static_fee,
    );

    // Predict unvault txid
    let predicted_unvault_txid = unvault_tx_template.compute_txid();
    println!("Predicted unvault txid: {}", predicted_unvault_txid);

    let unvault_amount = (utxos[0].value - args.static_fee).unwrap();
    let unvault_scriptpubkey = sp.clone();

    // Create unvault recovery tx using predicted txid and helper
    let unvault_outpoint = OutPoint {
        txid: predicted_unvault_txid,
        vout: 0,
    };

    let unvault_recovery_tx = create_unvault_recovery_transaction(
        unvault_outpoint,
        unvault_amount,
        recovery_script_pubkey.clone(),
        args.static_fee,
    );

    let mut unvault_recovery_psbt = Psbt::from_unsigned_tx(unvault_recovery_tx)
        .expect("Could not create unvault recovery PSBT");
    unvault_recovery_psbt.inputs = vec![Input {
        witness_utxo: Some(TxOut {
            value: unvault_amount,
            script_pubkey: unvault_scriptpubkey.clone(),
        }),
        ..Default::default()
    }];

    // Sign unvault recovery with nonce 1
    let (_, public_nonces_1, _, _) = aggregate_pubs(&sessions, Some(&coeff_salt), 1);

    let unvault_recovery_psbt_signed = sign_psbt(
        unvault_recovery_psbt,
        sessions.clone(),
        &key_agg_ctx,
        tweaked_aggregated_pubkey,
        &pubkeys,
        &public_nonces_1,
        &coeff_salt,
        "RECOVERY",
    )
    .await?;

    let unvault_recovery_tx_signed = unvault_recovery_psbt_signed.clone().extract_tx().unwrap();
    let serialized_unvault_recovery = consensus::encode::serialize_hex(&unvault_recovery_tx_signed);
    println!("Unvault Recovery Transaction Details: {:#?}", unvault_recovery_tx_signed);
    println!("Raw unvault recovery Transaction: {}", serialized_unvault_recovery);

    //sessions.iter().map(| s | {
    //    let session_data = SessionData {
    //        session_id: s.session_id.clone(),
    //        signing_session: s.clone(),
    //    };

    //    data.sessions
    //        .lock()
    //        .unwrap()
    //        .insert(s.session_id, session_data);
    //});

    // Prepare session data to return to depositor for later use during unvault
    let session_data = VaultSessionData {
        session_ids: sessions.iter().map(|s| s.session_id.clone()).collect(),
        coeff_salt: hex::encode(coeff_salt),
        pubkeys: pubkeys.iter().map(|pk| pk.to_string()).collect(),
        pubnonces: sessions
            .iter()
            .map(|s| s.init_resp.pubnonces.clone())
            .collect(),
        timelock_blocks: req.timelock_blocks,
        recovery_addr: req.recovery_addr.clone(),
    };

    let resp = VaultDepositResp {
        deposit_psbt: deposit_psbt,
        vault_recovery_psbt: vault_recovery_psbt,
        unvault_recovery_psbt: unvault_recovery_psbt_signed,
        vault_address: tap.to_string(),
        session_data,
    };
    Ok(web::Json(resp))
}

#[post("/vault/unvault")]
async fn sign_unvault(
    data: web::Data<AppState>,
    req: web::Json<VaultUnvaultReq>,
) -> actix_web::Result<impl Responder> {
    println!("Unvault request: {:?}", req);

    let secp = Secp256k1::new();
    let cfg = data.cfg.clone();
    let args = Args::parse();

    // Parse vault outpoint
    let vault_outpoint = OutPoint::from_str(&req.vault_outpoint)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid vault outpoint: {}", e)))?;

    // Parse destination address
    let destination_addr = Address::from_str(&req.destination_addr)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid destination address: {}", e)))?
        .require_network(args.network)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Address network mismatch: {}", e)))?;

    let session_data = &req.session_data;
    println!("Reusing vault session to sign unvault and final transactions:");
    println!("  - Session IDs: {:?}", session_data.session_ids);
    println!("  - Nonces remaining: 2 (indices 2 and 3)");

    // Parse stored coeff_salt
    let coeff_salt: [u8; 32] = hex::decode(&session_data.coeff_salt)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid coeff_salt hex: {}", e)))?
        .try_into()
        .map_err(|_| actix_web::error::ErrorBadRequest("coeff_salt must be 32 bytes"))?;

    // Reconstruct signing sessions from stored data
    let sessions: Vec<SigningSession> = cfg.signers
        .iter()
        .enumerate()
        .map(|(i, signer)| {
            let init_resp = InitResp {
                session_id: session_data.session_ids[i].clone(),
                pubkey: session_data.pubkeys[i].clone(),
                pubnonces: session_data.pubnonces[i].clone(),
            };
            SigningSession {
                signer: signer.clone(),
                session_id: session_data.session_ids[i].clone(),
                init_resp,
            }
        })
        .collect();

    // Aggregate pubkeys and get the vault key
    let (pubkeys, _, key_agg_ctx, _) = aggregate_pubs(&sessions, Some(&coeff_salt), 0);

    let untweaked_pubkey: Point = key_agg_ctx.aggregated_pubkey_untweaked();
    let tweaked_pubkey: Point = key_agg_ctx.aggregated_pubkey();
    let pk = bitcoin::secp256k1::PublicKey::from_slice(&untweaked_pubkey.serialize()).unwrap();
    let (xpub, _) = pk.x_only_public_key();

    // This is the same key used for both vault AND unvault
    let vault_scriptpubkey = Address::p2tr(&secp, xpub, None, args.network).script_pubkey();

    println!("Using aggregated pubkey: {}", xpub);

    // ========== Create deterministic unvault transaction ==========

    let vault_amount = Amount::from_sat(req.amount)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid vault amount: {}", e)))?;
    let unvault_amount = vault_amount.checked_sub(args.static_fee)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Fee exceeds vault amount"))?;

    // Use helper function to create the unvault transaction
    let unvault_tx = create_unvault_transaction(
        vault_outpoint,
        vault_amount,
        vault_scriptpubkey.clone(),
        args.static_fee,
    );

    let unvault_txid = unvault_tx.compute_txid();
    println!("Unvault txid: {}", unvault_txid);

    let mut unvault_psbt = Psbt::from_unsigned_tx(unvault_tx)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("PSBT creation failed: {}", e)))?;

    unvault_psbt.inputs = vec![Input {
        witness_utxo: Some(TxOut {
            value: vault_amount,
            script_pubkey: vault_scriptpubkey.clone(),
        }),
        ..Default::default()
    }];

    // Sign unvault with nonce 2
    let (_, public_nonces_2, _, _) = aggregate_pubs(&sessions, Some(&coeff_salt), 2);

    println!("\nSigning unvault transaction (using nonce 2)...");
    let signed_unvault_psbt = sign_psbt(
        unvault_psbt,
        sessions.clone(),
        &key_agg_ctx,
        tweaked_pubkey,
        &pubkeys,
        &public_nonces_2,
        &coeff_salt,
        "UNVAULT",
    )
    .await?;
    println!("✓ Unvault transaction signed");

    // ========== Create final spend transaction ==========

    let unvault_outpoint = OutPoint {
        txid: unvault_txid,
        vout: 0,
    };

    let final_tx = create_final_spend_transaction(
        unvault_outpoint,
        unvault_amount,
        destination_addr.script_pubkey(),
        session_data.timelock_blocks,
        args.static_fee,
    );

    let mut final_psbt = Psbt::from_unsigned_tx(final_tx)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("PSBT creation failed: {}", e)))?;

    final_psbt.inputs = vec![Input {
        witness_utxo: Some(TxOut {
            value: unvault_amount,
            script_pubkey: vault_scriptpubkey.clone(),
        }),
        ..Default::default()
    }];

    // Sign final spend with nonce 3
    let (_, public_nonces_3, _, _) = aggregate_pubs(&sessions, Some(&coeff_salt), 3);

    println!("\nSigning final spend transaction (using nonce 3)...");
    let signed_final_spend_psbt = sign_psbt(
        final_psbt,
        sessions.clone(),
        &key_agg_ctx,
        tweaked_pubkey,
        &pubkeys,
        &public_nonces_3,
        &coeff_salt,
        "FINAL",
    )
    .await?;
    println!("✓ Final spend transaction signed");

    // User already has unvault recovery tx from vault creation (pre-signed)
    let resp = VaultUnvaultResp {
        unvault_psbt: signed_unvault_psbt,
        final_spend_psbt: signed_final_spend_psbt,
        unvault_pubkey: xpub.to_string(),
    };

    Ok(web::Json(resp))
}

#[derive(Clone, Debug)]
struct SigningSession {
    signer: String,
    session_id: String,
    init_resp: InitResp,
}

async fn init_signer_sessions(
    cfg: &Config,
) -> Result<Vec<SigningSession>, Box<dyn std::error::Error>> {
    let mut sessions = vec![];

    for s in &cfg.signers {
        let id = hex::encode(rand::rng().random::<[u8; 32]>());
        let resp = reqwest::get(format!("http://{s}/init/{id}"))
            .await?
            .json::<InitResp>()
            .await?;
        println!("{resp:#?}");

        let session = SigningSession {
            signer: s.into(),
            session_id: id.clone(),
            init_resp: resp.clone(),
        };

        sessions.push(session);
    }

    Ok(sessions)
}

fn aggregate_partial_sigs(
    message: impl AsRef<[u8]>,
    key_agg_ctx: &KeyAggContext,
    sign_nonce: MaybePoint,
    unblinded_sigs: Vec<PartialSignature>,
) -> [u8; 64] {
    let final_signature: [u8; 64] = musig2::aggregate_partial_signatures_final_nonce(
        &key_agg_ctx,
        sign_nonce.try_into().unwrap(),
        unblinded_sigs,
        message,
    )
    .expect("error aggregating signatures");
    final_signature
}

fn unblind_partial_sigs(
    blinding_factors: &Vec<BlindingFactors>,
    sign_nonce: MaybePoint,
    partial_signatures: Vec<MaybeScalar>,
) -> Vec<PartialSignature> {
    let unblinded_sigs: Vec<PartialSignature> = partial_signatures
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if sign_nonce.has_even_y() {
                *s + blinding_factors[i].alpha
            } else {
                *s - blinding_factors[i].alpha
            }
        })
        .collect();
    unblinded_sigs
}

fn verify_partial_sigs(
    public_nonces: &Vec<PubNonce>,
    key_agg_ctx: &KeyAggContext,
    aggregated_pubkey: Point,
    blinding_factors: &Vec<BlindingFactors>,
    sign_nonce: MaybePoint,
    b: MaybeScalar,
    e: MaybeScalar,
    partial_signatures: &Vec<MaybeScalar>,
) {
    let challenge_parity = aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc();
    let nonce_parity = sign_nonce.parity();

    /// Signatures should be verified upon receipt and invalid signatures
    /// should be blamed on the signer who sent them.
    for (i, partial_signature) in partial_signatures.clone().into_iter().enumerate() {
        let their_pubkey: PublicKey = key_agg_ctx.get_pubkey(i).unwrap();
        let their_pubnonce = &public_nonces[i];

        let even_parity = bool::from(!challenge_parity);

        let key_coeff = key_agg_ctx.key_coefficient(their_pubkey).unwrap();
        let ep = if sign_nonce.has_even_y() ^ even_parity {
            key_coeff * e - blinding_factors[i].beta
        } else {
            key_coeff * e + blinding_factors[i].beta
        };

        let bp = b + blinding_factors[i].gamma;

        verify_partial_challenge(
            challenge_parity,
            partial_signature,
            nonce_parity,
            their_pubkey,
            &their_pubnonce,
            bp,
            ep,
        )
        .expect("received invalid signature from a peer");
    }
}

async fn request_partial_sigs(
    sessions: Vec<SigningSession>,
    key_agg_ctx: &KeyAggContext,
    aggregated_pubkey: Point,
    blinding_factors: &Vec<BlindingFactors>,
    sign_nonce: MaybePoint,
    b: MaybeScalar,
    e: MaybeScalar,
    message: String,
    pubkeys: &Vec<PublicKey>,
    public_nonces: &Vec<PubNonce>,
    coeff_salt: &[u8; 32],
    tx_type: &str,
) -> Result<Vec<MaybeScalar>, Box<dyn std::error::Error>> {
    let challenge_parity = aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc();
    let nonce_parity = sign_nonce.parity();

    let mut partial_signatures = vec![];
    for (i, session) in sessions.iter().enumerate() {
        let their_pubkey: PublicKey = key_agg_ctx.get_pubkey(i).unwrap();
        let key_coeff = key_agg_ctx.key_coefficient(their_pubkey).unwrap();

        let even_parity = bool::from(!challenge_parity);
        let ep = if sign_nonce.has_even_y() ^ even_parity {
            key_coeff * e - blinding_factors[i].beta
        } else {
            key_coeff * e + blinding_factors[i].beta
        };

        let bp = b + blinding_factors[i].gamma;

        let signer = session.signer.clone();
        let id = session.session_id.clone();
        let client = reqwest::Client::new();
        let url = format!("http://{signer}/sign/{id}");
        println!("url: {}", url);

        let zk_params = Params {
            coeff_salt: hex::encode(coeff_salt),
            blinding_factors: blinding_factors
                .iter()
                .map(|fac| {
                    (
                        hex::encode(fac.alpha),
                        hex::encode(fac.beta),
                        hex::encode(fac.gamma),
                    )
                })
                .collect(),
            pubkeys: pubkeys.iter().map(|pk| pk.to_string()).collect(),
            pubnonces: public_nonces.iter().map(|pk| pk.to_string()).collect(),
            message: message.clone(),
            signer_index: i,
        };

        println!("params: {}", serde_json::to_string(&zk_params).unwrap());

        // Generate ZK proof using zk-musig CLI
        let zk_params_json = serde_json::to_string(&zk_params)?;

        let mut cmd = Command::new("zk-musig");
        cmd.arg("prove")
            .arg("--config")
            .arg("-")
            .arg("--proof-type")
            .arg("fast")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Pass through RISC0_DEV_MODE if set
        if let Ok(dev_mode) = std::env::var("RISC0_DEV_MODE") {
            cmd.env("RISC0_DEV_MODE", dev_mode);
        }

        let mut child = cmd.spawn()?;

        // Write config to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(zk_params_json.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("zk-musig prove failed: {}", stderr);
            return Err(format!("ZK proof generation failed: {}", stderr).into());
        }

        let proof = String::from_utf8(output.stdout)?;

        let body = SignReq {
            session_id: id.clone(),
            challenge_parity: challenge_parity.unwrap_u8(),
            nonce_parity: nonce_parity.unwrap_u8(),
            b: bp.encode_hex(),
            e: hex::encode(ep),
            tx_type: tx_type.to_string(),
            zk_proof: proof,
        };

        let body_json = serde_json::to_string(&body).unwrap();
        // println!("body_json: {}", body_json);
        let resp = client.post(url).json(&body).send().await?;
        println!("{resp:#?}");
        let status = resp.status();
        println!("Response status: {}", status);

        if !status.is_success() {
            let error_body = resp.text().await?;
            println!("Error response body: {}", error_body);
            return Err(format!("Signer returned error: {} - {}", status, error_body).into());
        }

        let j = resp.json::<SignResp>().await?;
        println!("{j:#?}");

        let p = PartialSignature::from_hex(&j.sig).unwrap();
        partial_signatures.push(p);
    }
    Ok(partial_signatures)
}

#[derive(Debug, Clone)]
struct BlindingFactors {
    alpha: Scalar,
    beta: Scalar,
    gamma: Scalar,
}

fn gen_blinding_factors(num_signers: usize) -> Vec<BlindingFactors> {
    let blinding_seed = rand::rng().random::<[u8; 32]>();
    let mut blinding_factors = vec![];
    for i in 0..num_signers {
        let blind_hash0: [u8; 32] = Sha256::new()
            .chain_update(blinding_seed)
            .chain_update(&(i as u32).to_be_bytes())
            .chain_update(&(0 as u32).to_be_bytes())
            .finalize()
            .into();
        let k0 = Scalar::from_slice(&blind_hash0).unwrap();

        let blind_hash1: [u8; 32] = Sha256::new()
            .chain_update(blinding_seed)
            .chain_update(&(i as u32).to_be_bytes())
            .chain_update(&(1 as u32).to_be_bytes())
            .finalize()
            .into();
        let k1 = Scalar::from_slice(&blind_hash1).unwrap();

        let blind_hash2: [u8; 32] = Sha256::new()
            .chain_update(blinding_seed)
            .chain_update(&(i as u32).to_be_bytes())
            .chain_update(&(2 as u32).to_be_bytes())
            .finalize()
            .into();

        let k2 = Scalar::from_slice(&blind_hash2).unwrap();

        blinding_factors.push(BlindingFactors {
            alpha: k0,
            beta: k1,
            gamma: k2,
        });
    }

    blinding_factors
}

fn gen_coeff_salt() -> [u8; 32] {
    rand::rng().random::<[u8; 32]>()
}

fn aggregate_pubs(
    sessions: &Vec<SigningSession>,
    key_coeff_salt: Option<&[u8]>,
    nonce_index: usize,
) -> (Vec<PublicKey>, Vec<PubNonce>, KeyAggContext, AggNonce) {
    let (pubkeys, public_nonces): (Vec<PublicKey>, Vec<PubNonce>) = sessions
        .iter()
        .map(|session| {
            let resp = session.init_resp.clone();
            let pk = parse_pubkey(resp.pubkey.as_str());
            //println!("pk: {}", pk);
            let pn = PubNonce::from_hex(resp.pubnonces[nonce_index].as_str()).unwrap();
            (pk, pn)
        })
        .collect();

    let mut key_agg_ctx = KeyAggContext::new(pubkeys.clone(), key_coeff_salt).unwrap();
    let untweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();
    println!("untweaked agg pubkey X: {}", untweaked_aggregated_pubkey);
    key_agg_ctx = key_agg_ctx.with_unspendable_taproot_tweak().unwrap();
    let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();
    println!("taptweaked agg pubkey X: {}", aggregated_pubkey);

    // We manually aggregate the nonces together and then construct our partial signature.
    let aggregated_nonce: AggNonce = public_nonces.iter().sum();
    (pubkeys, public_nonces, key_agg_ctx, aggregated_nonce)
}

fn parse_pubkey(pub_str: &str) -> PublicKey {
    let pk = PublicKey::from_str(pub_str).unwrap();
    //let pk_bytes = hex::decode(pub_str).unwrap();
    //let pk = PublicKey::from_sec1_bytes(&pk_bytes).unwrap();

    //println!("sec1 pub: {}", hex::encode(pk_bytes));

    pk
}

// Helper function to create vault recovery transaction
// Spends from vault output to recovery address
fn create_vault_recovery_transaction(
    vault_outpoint: OutPoint,
    vault_amount: Amount,
    recovery_scriptpubkey: ScriptBuf,
    static_fee: Amount,
) -> Transaction {
    let recovery_amount = (vault_amount - static_fee).unwrap();

    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: vault_outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: recovery_amount,
            script_pubkey: recovery_scriptpubkey,
        }],
    }
}

// Helper function to create deterministic unvault transaction
// Spends from vault to unvault (using same key)
fn create_unvault_transaction(
    vault_outpoint: OutPoint,
    vault_amount: Amount,
    unvault_scriptpubkey: ScriptBuf,
    static_fee: Amount,
) -> Transaction {
    let unvault_amount = (vault_amount - static_fee).unwrap();

    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: vault_outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: unvault_amount,
            script_pubkey: unvault_scriptpubkey,
        }],
    }
}

// Helper function to create unvault recovery transaction
// Spends from unvault output to recovery address
fn create_unvault_recovery_transaction(
    unvault_outpoint: OutPoint,
    unvault_amount: Amount,
    recovery_scriptpubkey: ScriptBuf,
    static_fee: Amount,
) -> Transaction {
    let recovery_amount = (unvault_amount - static_fee).unwrap();

    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: unvault_outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: recovery_amount,
            script_pubkey: recovery_scriptpubkey,
        }],
    }
}

// Helper function to create final spend transaction
// Spends from unvault output to destination address with timelock
fn create_final_spend_transaction(
    unvault_outpoint: OutPoint,
    unvault_amount: Amount,
    destination_scriptpubkey: ScriptBuf,
    timelock_blocks: u32,
    static_fee: Amount,
) -> Transaction {
    let final_amount = (unvault_amount - static_fee).unwrap();

    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_height(timelock_blocks).unwrap(),
        input: vec![TxIn {
            previous_output: unvault_outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: final_amount,
            script_pubkey: destination_scriptpubkey,
        }],
    }
}

// Helper function to sign a PSBT using blind signatures from signers
async fn sign_psbt(
    mut psbt: Psbt,
    sessions: Vec<SigningSession>,
    key_agg_ctx: &KeyAggContext,
    tweaked_aggregated_pubkey: Point,
    pubkeys: &Vec<PublicKey>,
    public_nonces: &Vec<PubNonce>,
    coeff_salt: &[u8; 32],
    tx_type: &str,
) -> Result<Psbt, Box<dyn std::error::Error>> {
    // Extract the sighash message from the PSBT
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    let (msg, sighash_type) = psbt.sighash_taproot(0, &mut cache, None)?;
    let message = msg.as_ref();

    println!("Signing PSBT with tx_type: {}", tx_type);
    println!("msg: {:?}", msg);
    println!("sighash_type: {:?}", sighash_type);

    // Generate fresh blinding factors for this signing operation
    let num_signers = sessions.len();
    let blinding_factors = gen_blinding_factors(num_signers);

    // Calculate blinding factor adjustments
    let aas: MaybeScalar = blinding_factors.iter().map(|fac| fac.alpha).sum();
    let bbs: MaybePoint = blinding_factors
        .iter()
        .enumerate()
        .map(|(i, fac)| {
            let pubkey: Point = pubkeys[i].into();
            fac.beta * pubkey
        })
        .sum();

    let ggs: MaybePoint = blinding_factors
        .iter()
        .enumerate()
        .map(|(i, fac)| {
            let nonce = public_nonces[i].clone();
            fac.gamma * nonce.R2
        })
        .sum();

    // Calculate aggregated nonce from public nonces
    let aggregated_nonce: AggNonce = public_nonces.iter().sum();
    let b: MaybeScalar = aggregated_nonce.nonce_coefficient(tweaked_aggregated_pubkey, &message);
    let agg_nonce: MaybePoint = aggregated_nonce.final_nonce(b);
    let sign_nonce = agg_nonce + ggs + aas * G + bbs;

    let adaptor_point = MaybePoint::Infinity;
    let adapted_nonce = sign_nonce + adaptor_point;

    let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let e: MaybeScalar =
        compute_challenge_hash_tweak(&nonce_x_bytes, &tweaked_aggregated_pubkey.into(), &message);

    // Request partial signatures from signers
    let partial_signatures = request_partial_sigs(
        sessions,
        &key_agg_ctx,
        tweaked_aggregated_pubkey,
        &blinding_factors,
        sign_nonce,
        b,
        e,
        hex::encode(message),
        &pubkeys,
        &public_nonces,
        &coeff_salt,
        tx_type,
    )
    .await?;

    // Verify partial signatures
    verify_partial_sigs(
        &public_nonces,
        &key_agg_ctx,
        tweaked_aggregated_pubkey,
        &blinding_factors,
        sign_nonce,
        b,
        e,
        &partial_signatures,
    );

    // Unblind and aggregate signatures
    let unblinded_sigs = unblind_partial_sigs(&blinding_factors, sign_nonce, partial_signatures);
    let final_signature = aggregate_partial_sigs(message, &key_agg_ctx, sign_nonce, unblinded_sigs);

    // Verify the aggregated signature
    musig2::verify_single(tweaked_aggregated_pubkey, &final_signature, message)
        .expect("aggregated signature must be valid");

    let signature = schnorr::Signature::from_slice(&final_signature).unwrap();
    let signature = taproot::Signature {
        signature,
        sighash_type,
    };

    // Add signature to PSBT
    let mut sign_input = psbt.inputs[0].clone();
    sign_input.tap_key_sig = Some(signature);
    psbt.inputs[0] = sign_input;

    // Finalize the PSBT
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    Ok(psbt)
}

// Helper function to request recovery signatures from signers
