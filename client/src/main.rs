use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, Responder, Result, post, web};
use bitcoin::address::script_pubkey::ScriptBufExt;
use bitcoin::consensus_validation::TransactionExt;
use bitcoin::hashes::Hash;
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
    InitResp, SignReq, SignResp, VaultDepositReq, VaultDepositResp, VaultUnvaultReq,
    VaultUnvaultResp,
};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Mutex;

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
    sessions: Mutex<HashMap<String, SessionData>>,
    cfg: Config,
}

#[derive(Clone, Debug)]
struct SessionData {
    session_id: String,
    signing_session: SigningSession,
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
        sessions: Mutex::new(HashMap::new()),
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

    let (blinding_factors, coeff_salt) = gen_blinding_factors(num_signers);

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

    let spend_input = TxIn {
        previous_output: op,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    let spend_script_pubkey = Address::from_str(&req.recovery_addr)
        .unwrap()
        .require_network(args.network)
        .unwrap()
        .script_pubkey();

    let spend_out_amt = utxos[0].value - args.static_fee; // subtract static fee. TODO: use anchor instead?
    let spend_output = TxOut {
        value: spend_out_amt.unwrap(),
        script_pubkey: spend_script_pubkey.clone(),
    };

    let recovery_tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP 68.
        lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
        input: vec![spend_input],            // Input is 0-indexed.
        output: vec![spend_output],          // Outputs, order does not matter.
    };
    println!(
        "prevout: {}",
        hex::encode(consensus::encode::serialize(&utxos[0]))
    );

    let mut recovery_psbt =
        Psbt::from_unsigned_tx(recovery_tx.clone()).expect("Could not create PSBT");
    recovery_psbt.inputs = vec![Input {
        witness_utxo: Some(utxos[0].clone()),
        //tap_key_origins: origins[0].clone(),
        //tap_internal_key: Some(pk_input_1),
        //sighash_type: Some(ty),
        ..Default::default()
    }];

    // Sign the recovery PSBT using the extracted method
    let recovery_psbt = sign_psbt(
        recovery_psbt,
        sessions,
        &key_agg_ctx,
        tweaked_aggregated_pubkey,
        &blinding_factors,
        &pubkeys,
        &public_nonces,
        &coeff_salt,
        "VAULT",
    )
    .await?;

    let spend_tx = recovery_psbt.clone().extract_tx().unwrap();

    let serialized_signed_tx = consensus::encode::serialize_hex(&spend_tx);
    let serialized_funding_tx = consensus::encode::serialize_hex(&deposit_tx);
    println!("Transaction Details: {:#?}", spend_tx);
    // check with:
    // bitcoin-cli decoderawtransaction <RAW_TX> true
    println!("Raw deposit Transaction: {}", serialized_funding_tx);
    println!("Raw recovery Transaction: {}", serialized_signed_tx);

    let res = spend_tx
        .verify(|op| {
            println!("fetchin op {}", op);
            Some(utxos[0].clone())
        })
        .unwrap();
    println!("Transaction Result: {:#?}", res);

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

    let resp = VaultDepositResp {
        deposit_psbt: deposit_psbt,
        recovery_psbt: recovery_psbt,
        vault_address: tap.to_string(),
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

    // Parse destination and recovery addresses
    let destination_addr = Address::from_str(&req.destination_addr)
        .map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid destination address: {}", e))
        })?
        .assume_checked();

    let recovery_addr = Address::from_str(&req.recovery_addr)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid recovery address: {}", e)))?
        .assume_checked();

    // Initialize signing sessions with signers
    let sessions = init_signer_sessions(&cfg).await?;
    let num_signers = sessions.len();

    let (blinding_factors, coeff_salt) = gen_blinding_factors(num_signers);
    let (pubkeys, public_nonces, key_agg_ctx, _aggregated_nonce) =
        aggregate_pubs(&sessions, Some(&coeff_salt), 1);

    // Create the same aggregated key as the original vault
    let untweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey_untweaked();
    let pk = bitcoin::secp256k1::PublicKey::from_slice(&untweaked_aggregated_pubkey.serialize())
        .unwrap();
    let (xpub, _) = pk.x_only_public_key();

    println!("Unvault aggregated pubkey: {}", xpub);

    // Create the three transactions
    let unvault_psbt = create_unvault_transaction(&req, &secp, xpub, args.static_fee)?;
    let recovery_psbt = create_recovery_transaction(&req, &unvault_psbt, &recovery_addr, args.static_fee)?;
    let final_spend_psbt = create_final_spend_transaction(&req, &unvault_psbt, &destination_addr, args.static_fee)?;

    // TODO: Get signatures from signers for all three transactions
    // This would use request_unvault_signatures() to get blind signatures

    println!("Created unvault transactions:");
    println!("Unvault PSBT: {:?}", unvault_psbt.unsigned_tx);
    println!("Recovery PSBT: {:?}", recovery_psbt.unsigned_tx);
    println!("Final spend PSBT: {:?}", final_spend_psbt.unsigned_tx);

    let resp = VaultUnvaultResp {
        unvault_psbt,
        recovery_psbt,
        final_spend_psbt,
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
        let id = hex::encode(rand::thread_rng().random::<[u8; 32]>());
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

        // TODO: Replace with actual ZK proof generation when available
        // let output = Command::new("/Users/johan.halseth/code/rust/zk-musig/target/release/host")
        //     //.env("RISC0_DEV_MODE", "true")
        //     .arg(format!("--prove={}", serde_json::to_string(&zk_params).unwrap()))
        //     .output()?;
        //
        // let proof = String::from_utf8(output.stdout).unwrap();
        // let proof = proof.strip_suffix("\n").unwrap();
        let proof = "dummy_zk_proof";
        //println!("output: {}", proof);
        fs::write("receipt.txt", proof).expect("Should be able to write to `/foo/tmp`");

        //let proof =
        //    fs::read_to_string("receipt.txt").expect("Should be able to read from `/foo/tmp`");

        // TODO: must prove that all these values are generated correctly
        // TODO: blind b, parity?, key_coeff?
        let body = SignReq {
            session_id: id.clone(),
            challenge_parity: challenge_parity.unwrap_u8(),
            nonce_parity: nonce_parity.unwrap_u8(),
            b: bp.encode_hex(),
            e: hex::encode(ep),
            tx_type: tx_type.to_string(),
            zk_proof: proof.to_string(),
        };
        // TODO: attach ZK proof that these values are createed accoring to the protocol

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

fn gen_blinding_factors(num_signers: usize) -> (Vec<BlindingFactors>, [u8; 32]) {
    let blinding_seed = rand::thread_rng().random::<[u8; 32]>();
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

    let coeff_salt: [u8; 32] = Sha256::new()
        .chain_update(blinding_seed)
        .chain_update(&(num_signers as u32).to_be_bytes())
        .chain_update(&(3 as u32).to_be_bytes())
        .finalize()
        .into();

    (blinding_factors, coeff_salt)
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

// Helper function to create unvault transaction
fn create_unvault_transaction(
    req: &VaultUnvaultReq,
    secp: &Secp256k1<All>,
    unvault_pubkey: XOnlyPublicKey,
    static_fee: Amount,
) -> actix_web::Result<Psbt> {
    use bitcoin::ScriptBuf;

    // Parse the vault outpoint
    let vault_outpoint = OutPoint::from_str(&req.vault_outpoint)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid vault outpoint: {}", e)))?;

    // Create input spending from vault
    let input = TxIn {
        previous_output: vault_outpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    // Calculate output amount after fee
    let input_amount = Amount::from_sat(req.amount)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid amount: {}", e)))?;
    let output_amount = input_amount.checked_sub(static_fee)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Fee exceeds input amount"))?;

    // Create output with same pubkey (unvault output)
    let unvault_script = ScriptBuf::new_p2tr(secp, unvault_pubkey, None);
    let output = TxOut {
        value: output_amount,
        script_pubkey: unvault_script,
    };

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to create PSBT: {}", e))
    })?;

    // Add witness_utxo for the vault input
    let vault_script = ScriptBuf::new_p2tr(secp, unvault_pubkey, None);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(req.amount)
            .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid amount: {}", e)))?,
        script_pubkey: vault_script,
    });

    Ok(psbt)
}

// Helper function to create recovery transaction
fn create_recovery_transaction(
    req: &VaultUnvaultReq,
    unvault_psbt: &Psbt,
    recovery_addr: &Address,
    static_fee: Amount,
) -> actix_web::Result<Psbt> {
    use bitcoin::ScriptBuf;

    // Create input spending from unvault output
    let unvault_tx = &unvault_psbt.unsigned_tx;
    let unvault_outpoint = OutPoint {
        txid: unvault_tx.compute_txid(),
        vout: 0, // First output is the unvault output
    };

    let input = TxIn {
        previous_output: unvault_outpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    // Calculate output amount after fee (use unvault output amount, not original vault amount)
    let unvault_output_amount = unvault_tx.output[0].value;
    let output_amount = unvault_output_amount.checked_sub(static_fee)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Fee exceeds unvault output amount"))?;

    // Create output to recovery address
    let output = TxOut {
        value: output_amount,
        script_pubkey: recovery_addr.script_pubkey(),
    };

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO, // Recovery can be immediate
        input: vec![input],
        output: vec![output],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to create PSBT: {}", e))
    })?;

    // Add witness_utxo for the unvault input
    psbt.inputs[0].witness_utxo = Some(unvault_tx.output[0].clone());

    Ok(psbt)
}

// Helper function to create final spend transaction
fn create_final_spend_transaction(
    req: &VaultUnvaultReq,
    unvault_psbt: &Psbt,
    destination_addr: &Address,
    static_fee: Amount,
) -> actix_web::Result<Psbt> {
    use bitcoin::ScriptBuf;

    // Create input spending from unvault output
    let unvault_tx = &unvault_psbt.unsigned_tx;
    let unvault_outpoint = OutPoint {
        txid: unvault_tx.compute_txid(),
        vout: 0, // First output is the unvault output
    };

    let input = TxIn {
        previous_output: unvault_outpoint,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    // Calculate output amount after fee (use unvault output amount, not original vault amount)
    let unvault_output_amount = unvault_tx.output[0].value;
    let output_amount = unvault_output_amount.checked_sub(static_fee)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Fee exceeds unvault output amount"))?;

    // Create output to destination address
    let output = TxOut {
        value: output_amount,
        script_pubkey: destination_addr.script_pubkey(),
    };

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_height(req.timelock_blocks).unwrap(),
        input: vec![input],
        output: vec![output],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to create PSBT: {}", e))
    })?;

    // Add witness_utxo for the unvault input
    psbt.inputs[0].witness_utxo = Some(unvault_tx.output[0].clone());

    Ok(psbt)
}

// Helper function to sign a PSBT using blind signatures from signers
async fn sign_psbt(
    mut psbt: Psbt,
    sessions: Vec<SigningSession>,
    key_agg_ctx: &KeyAggContext,
    tweaked_aggregated_pubkey: Point,
    blinding_factors: &Vec<BlindingFactors>,
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
async fn request_recovery_signatures(
    sessions: &[SigningSession],
    key_agg_ctx: &KeyAggContext,
    blinding_factors: &[BlindingFactors],
    pubkeys: &[PublicKey],
    public_nonces: &[PubNonce],
    coeff_salt: &[u8],
    recovery_psbt: Psbt,
) -> Result<Psbt, Box<dyn std::error::Error>> {
    // This would implement the blind signing protocol for the recovery transaction
    // For now, return the unsigned PSBT as we haven't fully implemented the signing
    // In a real implementation, this would:
    // 1. Extract sighash from recovery PSBT
    // 2. Call request_partial_sigs with "RECOVERY" transaction type
    // 3. Aggregate the partial signatures
    // 4. Return the fully signed recovery PSBT

    println!("Requesting recovery signatures for vault deposit");

    // TODO: Extract message/sighash from recovery PSBT and call request_partial_sigs
    // with "RECOVERY" transaction type once PSBT signing is fully integrated

    Ok(recovery_psbt)
}

// Helper function to request unvault signatures from signers
async fn request_unvault_signatures(
    sessions: &[SigningSession],
    key_agg_ctx: &KeyAggContext,
    blinding_factors: &[BlindingFactors],
    pubkeys: &[PublicKey],
    public_nonces: &[PubNonce],
    coeff_salt: &[u8],
    unvault_psbt: Psbt,
    final_spend_psbt: Psbt,
) -> Result<(Psbt, Psbt), Box<dyn std::error::Error>> {
    // This would implement the blind signing protocol for unvault transactions
    // For now, return the unsigned PSBTs
    // In a real implementation, this would:
    // 1. Extract sighashes from both PSBTs
    // 2. Call request_partial_sigs with "UNVAULT" for the first transaction
    // 3. Call request_partial_sigs with "FINAL" for the second transaction
    // 4. Aggregate the partial signatures for both transactions
    // 5. Return the fully signed PSBTs

    println!("Requesting unvault signatures for unvault and final spend transactions");

    // TODO: Extract messages/sighashes from both PSBTs and call request_partial_sigs
    // with appropriate transaction types ("UNVAULT" and "FINAL")

    Ok((unvault_psbt, final_spend_psbt))
}
