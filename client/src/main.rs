use clap::Parser;
use hex::ToHex;
use musig2::secp::{G, MaybePoint, MaybeScalar, Point, Scalar};
use musig2::{
    AggNonce, KeyAggContext, PartialSignature, PubNonce, compute_challenge_hash_tweak,
    verify_partial_challenge,
};
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::{InitResp, SignReq, SignResp};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Args {
    #[arg(long)]
    cfg: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    pub signers: Vec<String>,
}

struct SigningSession {
    signer: String,
    session_id: String,
    init_resp: InitResp,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let message = "hello interwebz!";

    let args = Args::parse();
    let cfg: Config = serde_json::from_str(&args.cfg.unwrap()).unwrap();
    println!("config: {:?}", cfg);

    let mut sessions = vec![];

    for s in cfg.signers {
        let id = hex::encode(rand::thread_rng().random::<[u8; 32]>());
        let resp = reqwest::get(format!("http://{s}/init/{id}"))
            .await?
            .json::<InitResp>()
            .await?;
        println!("{resp:#?}");

        let session = SigningSession {
            signer: s,
            session_id: id.clone(),
            init_resp: resp.clone(),
        };

        sessions.push(session);
    }

    let num_signers = sessions.len();
    println!("num signers: {}", num_signers);

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

    let key_agg_ctx = KeyAggContext::new(pubkeys.clone()).unwrap();
    let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();
    println!("agg pubkey X: {}", aggregated_pubkey);

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

    // We manually aggregate the nonces together and then construct our partial signature.
    let aggregated_nonce: AggNonce = public_nonces.iter().sum();

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
        compute_challenge_hash_tweak(&nonce_x_bytes, &aggregated_pubkey.into(), &message);
    let ee: Scalar = e.try_into().unwrap();

    let pubkey: Point = pubkeys[0].into();

    let parity = aggregated_pubkey.parity(); // ^ key_agg_ctx.parity_acc;
    let nonce_parity = sign_nonce.parity();

    let mut partial_signatures = vec![];
    for (i, session) in sessions.iter().enumerate() {
        let their_pubkey: PublicKey = key_agg_ctx.get_pubkey(i).unwrap();
        let key_coeff = key_agg_ctx.key_coefficient(their_pubkey).unwrap();

        let ep = if sign_nonce.has_even_y() ^ aggregated_pubkey.has_even_y() {
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
            key_parity: parity.unwrap_u8(),
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

    /// Signatures should be verified upon receipt and invalid signatures
    /// should be blamed on the signer who sent them.
    for (i, partial_signature) in partial_signatures.clone().into_iter().enumerate() {
        let their_pubkey: PublicKey = key_agg_ctx.get_pubkey(i).unwrap();
        let their_pubnonce = &public_nonces[i];

        let ep = if sign_nonce.has_even_y() ^ aggregated_pubkey.has_even_y() {
            e - blinding_factors[i].1
        } else {
            e + blinding_factors[i].1
        };

        verify_partial_challenge(
            key_agg_ctx.key_coefficient(their_pubkey).unwrap(),
            parity,
            partial_signature,
            nonce_parity,
            their_pubkey,
            &their_pubnonce,
            ep,
        )
        .expect("received invalid signature from a peer");
    }

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

    let final_signature: [u8; 64] = musig2::aggregate_partial_signatures_final_nonce(
        &key_agg_ctx,
        sign_nonce.try_into().unwrap(),
        unblinded_sigs,
        message,
    )
    .expect("error aggregating signatures");

    musig2::verify_single(aggregated_pubkey, &final_signature, message)
        .expect("aggregated signature must be valid");

    Ok(())
}
