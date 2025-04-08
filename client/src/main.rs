use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, Responder, Result, post, web};
use bitcoin::KnownHrp::Mainnet;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    Address, Network,
};
use clap::Parser;
use hex::ToHex;
use musig2::secp::{G, MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce, compute_challenge_hash_tweak,
    verify_partial_challenge,
};
use rand::Rng;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::{InitResp, SignPsbtReq, SignPsbtResp, SignReq, SignResp};
use std::collections::HashMap;
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

    let (pubkeys, public_nonces, key_agg_ctx, aggregated_nonce) = aggregate_pubs(&sessions);

    let untweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey_untweaked();
    println!("untweaked agg pubkey X: {}", untweaked_aggregated_pubkey);
    let tweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

    let blinding_factors = gen_blinding_factors(num_signers);

    let aas: MaybeScalar = blinding_factors.iter().map(|(a, b)| *a).sum();
    let bbs: MaybePoint = blinding_factors
        .iter()
        .enumerate()
        .map(|(i, (a, b))| {
            let pubkey: Point = pubkeys[i].into();
            let c = key_agg_ctx.key_coefficient(pubkey).unwrap();
            let bc = *b * c;
            bc * pubkey
        })
        .sum();

    let agg_nonce: MaybePoint = aggregated_nonce.final_nonce();
    let sign_nonce = agg_nonce + aas * G + bbs;

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
        e,
    )
    .await?;

    verify_partial_sigs(
        &public_nonces,
        &key_agg_ctx,
        tweaked_aggregated_pubkey,
        &blinding_factors,
        sign_nonce,
        e,
        &partial_signatures,
    );

    let unblinded_sigs = unblind_partial_sigs(blinding_factors, sign_nonce, partial_signatures);

    let final_signature = aggregate_partial_sigs(message, &key_agg_ctx, sign_nonce, unblinded_sigs);

    musig2::verify_single(tweaked_aggregated_pubkey, &final_signature, message)
        .expect("aggregated signature must be valid");

    Ok(())
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

    let sessions = init_signer_sessions(&cfg).await?;
    let num_signers = sessions.len();

    let (pubkeys, public_nonces, key_agg_ctx, aggregated_nonce) = aggregate_pubs(&sessions);

    let untweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey_untweaked();
    println!("untweaked agg pubkey X: {}", untweaked_aggregated_pubkey);
    let tweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

    let pk = bitcoin::secp256k1::PublicKey::from_slice(&untweaked_aggregated_pubkey.serialize())
        .unwrap();
    let (xpub, _) = pk.x_only_public_key();
    println!("agg pubkey: {} x-only:{}", pk, xpub);

    let tap = Address::p2tr(&secp, xpub, None, Mainnet);
    let sp = tap.script_pubkey();

    let script_pubkey_1 =
        Address::from_str("bc1p80lanj0xee8q667aqcnn0xchlykllfsz3gu5skfv9vjsytaujmdqtv52vu")
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
            .script_pubkey();

    let mut psbt = req.psbt.clone();
    if let Some(output) = psbt.unsigned_tx.output.get_mut(0) {
        output.script_pubkey = sp.clone();
    }

    println!("psbt: {:?}", psbt);

    let body_json = serde_json::to_string(&psbt).unwrap();
    println!("body_json: {}", body_json);

    let resp = SignPsbtResp {};
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
    blinding_factors: Vec<(Scalar, Scalar)>,
    sign_nonce: MaybePoint,
    partial_signatures: Vec<MaybeScalar>,
) -> Vec<PartialSignature> {
    let unblinded_sigs: Vec<PartialSignature> = partial_signatures
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if sign_nonce.has_even_y() {
                *s + blinding_factors[i].0
            } else {
                *s - blinding_factors[i].0
            }
        })
        .collect();
    unblinded_sigs
}

fn verify_partial_sigs(
    public_nonces: &Vec<PubNonce>,
    key_agg_ctx: &KeyAggContext,
    aggregated_pubkey: Point,
    blinding_factors: &Vec<(Scalar, Scalar)>,
    sign_nonce: MaybePoint,
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

        let ep = if sign_nonce.has_even_y() ^ even_parity {
            e - blinding_factors[i].1
        } else {
            e + blinding_factors[i].1
        };

        verify_partial_challenge(
            key_agg_ctx.key_coefficient(their_pubkey).unwrap(),
            challenge_parity,
            partial_signature,
            nonce_parity,
            their_pubkey,
            &their_pubnonce,
            ep,
        )
        .expect("received invalid signature from a peer");
    }
}

async fn request_partial_sigs(
    sessions: Vec<SigningSession>,
    key_agg_ctx: &KeyAggContext,
    aggregated_pubkey: Point,
    blinding_factors: &Vec<(Scalar, Scalar)>,
    sign_nonce: MaybePoint,
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
            e - blinding_factors[i].1
        } else {
            e + blinding_factors[i].1
        };

        let signer = session.signer.clone();
        let id = session.session_id.clone();
        let client = reqwest::Client::new();
        let url = format!("http://{signer}/sign/{id}");
        println!("url: {}", url);

        let body = SignReq {
            session_id: id.clone(),
            challenge_parity: challenge_parity.unwrap_u8(),
            nonce_parity: nonce_parity.unwrap_u8(),
            key_coeff: key_coeff.encode_hex(),
            e: hex::encode(ep),
        };
        let body_json = serde_json::to_string(&body).unwrap();
        println!("body_json: {}", body_json);
        let resp = client
            .post(url)
            .json(&body)
            .send()
            .await?
            .json::<SignResp>()
            .await?;
        println!("{resp:#?}");

        let p = PartialSignature::from_hex(&resp.sig).unwrap();
        partial_signatures.push(p);
    }
    Ok(partial_signatures)
}

fn gen_blinding_factors(num_signers: usize) -> Vec<(Scalar, Scalar)> {
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
        blinding_factors.push((k0, k1));
    }
    blinding_factors
}

fn aggregate_pubs(
    sessions: &Vec<SigningSession>,
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

    let mut key_agg_ctx = KeyAggContext::new(pubkeys.clone()).unwrap();
    let untweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();
    println!("untweaked agg pubkey X: {}", untweaked_aggregated_pubkey);
    key_agg_ctx = key_agg_ctx.with_unspendable_taproot_tweak().unwrap();
    let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();
    println!("taptweaked agg pubkey X: {}", aggregated_pubkey);

    // We manually aggregate the nonces together and then construct our partial signature.
    let aggregated_nonce: AggNonce = public_nonces.iter().sum();
    (pubkeys, public_nonces, key_agg_ctx, aggregated_nonce)
}
