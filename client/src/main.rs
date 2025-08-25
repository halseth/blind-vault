use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, Responder, Result, post, web};
use bitcoin::KnownHrp::Mainnet;
use bitcoin::consensus_validation::TransactionExt;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Input;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, consensus, taproot, transaction,
};
use clap::Parser;
use hex::ToHex;
use musig2::secp::{G, MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce, compute_challenge_hash_tweak,
    verify_partial_challenge,
};
use rand::Rng;
use secp256k1::{PublicKey, SecretKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::{InitResp, SignPsbtReq, SignPsbtResp, SignReq, SignResp};
use std::collections::{BTreeMap, HashMap};
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

    #[arg(long)]
    server: bool,

    /// Network to use.
    #[arg(long, default_value_t = Network::Signet)]
    network: Network,
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
    init_resp: InitResp,
    secret_key: SecretKey,
    secret_nonce: SecNonce,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let cfg: Config = serde_json::from_str(&args.cfg.unwrap()).unwrap();
    println!("config: {:?}", cfg);

    if !args.server {
        run_example(cfg).await.unwrap();
        return Ok(());
    }

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
            .service(sign_psbt)
    })
    .bind(bind)?
    .run()
    .await
}

async fn run_example(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let message = "hello interwebz!";

    let sessions = init_signer_sessions(&cfg).await?;
    let num_signers = sessions.len();
    println!("num signers: {}", num_signers);
    let (blinding_factors , coeff_salt) = gen_blinding_factors(num_signers);

    let (
        pubkeys,
        public_nonces,
        key_agg_ctx,
        aggregated_nonce,
    ) = aggregate_pubs(&sessions, Some(&coeff_salt));

    let untweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey_untweaked();
    println!("untweaked agg pubkey X: {}", untweaked_aggregated_pubkey);
    let tweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

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

    let b: MaybeScalar = aggregated_nonce.nonce_coefficient(tweaked_aggregated_pubkey, &message);
    let agg_nonce: MaybePoint = aggregated_nonce.final_nonce(b);
    let sign_nonce = agg_nonce + ggs + aas * G + bbs;

    let adaptor_point = MaybePoint::Infinity;
    let adapted_nonce = sign_nonce + adaptor_point;

    let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let e: MaybeScalar =
        compute_challenge_hash_tweak(&nonce_x_bytes, &tweaked_aggregated_pubkey.into(), &message);

    let partial_signatures = request_partial_sigs(
        sessions,
        &key_agg_ctx,
        tweaked_aggregated_pubkey,
        &blinding_factors,
        sign_nonce,
        b,
        e,
    )
    .await?;

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

    let unblinded_sigs = unblind_partial_sigs(blinding_factors, sign_nonce, partial_signatures);

    let final_signature = aggregate_partial_sigs(message, &key_agg_ctx, sign_nonce, unblinded_sigs);

    musig2::verify_single(tweaked_aggregated_pubkey, &final_signature, message)
        .expect("aggregated signature must be valid");

    Ok(())
}
const XPRIV: &str = "xprv9tuogRdb5YTgcL3P8Waj7REqDuQx4sXcodQaWTtEVFEp6yRKh1CjrWfXChnhgHeLDuXxo2auDZegMiVMGGxwxcrb2PmiGyCngLxvLeGsZRq";
const BIP86_DERIVATION_PATH: &str = "m/86'/0'/0'";
const MASTER_FINGERPRINT: &str = "9680603f";

fn dummy_unspent_transaction_outputs() -> Vec<(OutPoint, TxOut)> {
    let DUMMY_UTXO_AMOUNT_INPUT_1: Amount = Amount::from_sat(20_000_000).unwrap();
    let DUMMY_UTXO_AMOUNT_INPUT_2: Amount = Amount::from_sat(10_000_000).unwrap();
    let SPEND_AMOUNT: Amount = Amount::from_sat(25_000_000).unwrap();
    let CHANGE_AMOUNT: Amount = Amount::from_sat(4_990_000).unwrap(); // 10_000 sat fee.

    let script_pubkey_1 =
        Address::from_str("bc1p80lanj0xee8q667aqcnn0xchlykllfsz3gu5skfv9vjsytaujmdqtv52vu")
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();

    let out_point_1 = OutPoint {
        txid: Txid::COINBASE_PREVOUT,
        vout: 0,
    };

    let utxo_1 = TxOut {
        value: DUMMY_UTXO_AMOUNT_INPUT_1,
        script_pubkey: script_pubkey_1,
    };

    let script_pubkey_2 =
        Address::from_str("bc1pfd0jmmdnp278vppcw68tkkmquxtq50xchy7f6wdmjtjm7fgsr8dszdcqce")
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();

    let out_point_2 = OutPoint {
        txid: Txid::COINBASE_PREVOUT,
        vout: 1,
    };

    let utxo_2 = TxOut {
        value: DUMMY_UTXO_AMOUNT_INPUT_2,
        script_pubkey: script_pubkey_2,
    };
    vec![(out_point_1, utxo_1), (out_point_2, utxo_2)]
}

#[post("/psbt")]
async fn sign_psbt(
    data: web::Data<AppState>,
    //id: web::Path<String>,
    req: web::Json<SignPsbtReq>,
) -> actix_web::Result<impl Responder> {
    println!("req: {:?}", req);

    let secp = Secp256k1::new();

    let cfg = data.cfg.clone();
    let args = Args::parse();

    let sessions = init_signer_sessions(&cfg).await?;
    let num_signers = sessions.len();

    let (blinding_factors , coeff_salt) = gen_blinding_factors(num_signers);

    let (
        pubkeys,
        public_nonces,
        key_agg_ctx,
        aggregated_nonce,
    ) = aggregate_pubs(&sessions, Some(&coeff_salt));

    let untweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey_untweaked();
    println!("untweaked agg pubkey X: {}", untweaked_aggregated_pubkey);
    let tweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

    let pk = bitcoin::secp256k1::PublicKey::from_slice(&untweaked_aggregated_pubkey.serialize())
        .unwrap();
    let (xpub, _) = pk.x_only_public_key();
    println!("agg pubkey: {} x-only:{}", pk, xpub);

    let tap = Address::p2tr(&secp, xpub, None, Mainnet);
    let sp = tap.script_pubkey();

    let mut deposit_psbt = req.psbt.clone();
    if let Some(output) = deposit_psbt.unsigned_tx.output.get_mut(0) {
        output.script_pubkey = sp.clone();
    }

    println!("deposit: {:?}", deposit_psbt);

    let body_json = serde_json::to_string(&deposit_psbt).unwrap();
    println!("body_json: {}", body_json);

    // Create transaction that spends from this output (just into hardcoded dummy address for now).
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

    let spend_script_pubkey = Address::from_str(&req.fallback_addr)
        .unwrap()
        .require_network(args.network)
        .unwrap()
        .script_pubkey();

    let spend_out_amt = utxos[0].value - Amount::from_sat(500).unwrap(); // subtract static fee
    let spend_output = TxOut {
        value: spend_out_amt.unwrap(),
        script_pubkey: spend_script_pubkey.clone(),
    };

    let spending_tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP 68.
        lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
        input: vec![spend_input],            // Input is 0-indexed.
        output: vec![spend_output],          // Outputs, order does not matter.
    };
    println!(
        "prevout: {}",
        hex::encode(consensus::encode::serialize(&utxos[0]))
    );

    let mut spend_psbt =
        Psbt::from_unsigned_tx(spending_tx.clone()).expect("Could not create PSBT");
    spend_psbt.inputs = vec![Input {
        witness_utxo: Some(utxos[0].clone()),
        //tap_key_origins: origins[0].clone(),
        //tap_internal_key: Some(pk_input_1),
        //sighash_type: Some(ty),
        ..Default::default()
    }];

    let mut cache = SighashCache::new(&spending_tx);
    let (msg, sighash_type) = spend_psbt.sighash_taproot(0, &mut cache, None).unwrap();
    let message = msg.as_ref();

    println!("msg: {:?}", msg);
    println!("sighash_type: {:?}", sighash_type);


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


    let b: MaybeScalar = aggregated_nonce.nonce_coefficient(tweaked_aggregated_pubkey, &message);
    let agg_nonce: MaybePoint = aggregated_nonce.final_nonce(b);
    let sign_nonce = agg_nonce + ggs + aas * G + bbs;

    let adaptor_point = MaybePoint::Infinity;
    let adapted_nonce = sign_nonce + adaptor_point;

    let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let e: MaybeScalar =
        compute_challenge_hash_tweak(&nonce_x_bytes, &tweaked_aggregated_pubkey.into(), &message);

    let partial_signatures = request_partial_sigs(
        sessions,
        &key_agg_ctx,
        tweaked_aggregated_pubkey,
        &blinding_factors,
        sign_nonce,
        b,
        e,
    )
    .await?;

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

    let unblinded_sigs = unblind_partial_sigs(blinding_factors, sign_nonce, partial_signatures);

    let final_signature = aggregate_partial_sigs(message, &key_agg_ctx, sign_nonce, unblinded_sigs);

    musig2::verify_single(tweaked_aggregated_pubkey, &final_signature, message)
        .expect("aggregated signature must be valid");

    let signature = schnorr::Signature::from_slice(&final_signature).unwrap();

    let signature = taproot::Signature {
        signature,
        sighash_type,
    };

    let mut sign_input = spend_psbt.inputs[0].clone();

    sign_input.tap_key_sig = Some(signature);
    spend_psbt.inputs[0] = sign_input;

    // Step 4: Finalizer role; that finalizes the PSBT.
    spend_psbt.inputs.iter_mut().for_each(|input| {
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

    let spend_tx = spend_psbt.clone().extract_tx().unwrap();

    let serialized_signed_tx = consensus::encode::serialize_hex(&spend_tx);
    let serialized_funding_tx = consensus::encode::serialize_hex(&deposit_tx);
    println!("Transaction Details: {:#?}", spend_tx);
    // check with:
    // bitcoin-cli decoderawtransaction <RAW_TX> true
    println!("Raw deposit Transaction: {}", serialized_funding_tx);
    println!("Raw spending Transaction: {}", serialized_signed_tx);

    let res = spend_tx
        .verify(|op| {
            println!("fetchin op {}", op);
            Some(utxos[0].clone())
        })
        .unwrap();
    println!("Transaction Result: {:#?}", res);

    let resp = SignPsbtResp {
        deposit_psbt: deposit_psbt,
        spend_psbt: spend_psbt,
    };
    Ok(web::Json(resp))
}

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
    blinding_factors: Vec<BlindingFactors>,
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

        // TODO: must prove that all these values are generated correctly
        // TODO: blind b, parity?, key_coeff?
        let body = SignReq {
            session_id: id.clone(),
            challenge_parity: challenge_parity.unwrap_u8(),
            nonce_parity: nonce_parity.unwrap_u8(),
            b: bp.encode_hex(),
            e: hex::encode(ep),
        };
        let body_json = serde_json::to_string(&body).unwrap();
        println!("body_json: {}", body_json);
        let resp = client
            .post(url)
            .json(&body)
            .send()
            .await?;
        println!("{resp:#?}");
        let j = resp.json::<SignResp>()
            .await?;
        println!("{j:#?}");

        let p = PartialSignature::from_hex(&j.sig).unwrap();
        partial_signatures.push(p);
    }
    Ok(partial_signatures)
}

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

        blinding_factors.push(BlindingFactors{ alpha: k0, beta: k1, gamma: k2 });
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
) -> (Vec<PublicKey>, Vec<PubNonce>, KeyAggContext, AggNonce) {
    let (pubkeys, public_nonces): (Vec<PublicKey>, Vec<PubNonce>) = sessions
        .iter()
        .map(|session| {
            let resp = session.init_resp.clone();
            let pk = PublicKey::from_str(resp.pubkey.as_str()).unwrap();
            println!("pk: {}", pk);
            let pn = PubNonce::from_hex(resp.pubnonce.as_str()).unwrap();
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
