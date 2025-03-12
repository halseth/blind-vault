use musig2::{tagged_hashes, KeyAggContext};
use musig2::{AggNonce, SecNonce};
use musig2::{
    CompactSignature, FirstRound, PartialSignature, PubNonce, SecNonceSpices, SecondRound,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest,Sha256};

fn main() {
    println!("Hello, world!");

 //   let pubkeys = [
 //       "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"
 //           .parse::<PublicKey>()
 //           .unwrap(),
 //       "02f3b071c064f115ca762ed88c3efd1927ea657c7949698b77255ea25751331f0b"
 //           .parse::<PublicKey>()
 //           .unwrap(),
 //       "03204ea8bc3425b2cbc9cb20617f67dc6b202467591d0b26d059e370b71ee392eb"
 //           .parse::<PublicKey>()
 //           .unwrap(),
 //   ];

    let num_signers = 3;
    let seckey_seed = [0xABu8; 32];

    let secp = Secp256k1::new();

    let signer_index = 2;
 //   let seckey: SecretKey = "10e7721a3aa6de7a98cecdbd7c706c836a907ca46a43235a7b498b12498f98f0"
 //       .parse()
 //       .unwrap();

    let mut seckeys = vec![];
    for i in 0..num_signers {
        let seed_hash: [u8; 32] = Sha256::new()
            .chain_update(seckey_seed)
            .chain_update(&(i as u32).to_be_bytes())
            .finalize()
            .into();
        let k = SecretKey::from_byte_array(&seed_hash).unwrap();
        seckeys.push(k);
    }

    let pubkeys: Vec<PublicKey> = seckeys.iter().map(|s| s.public_key(&secp)).collect();

    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();

    // This is the key which the group has control over.
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
 //   assert_eq!(
 //       aggregated_pubkey,
 //       "02e272de44ea720667aba55341a1a761c0fc8fbe294aa31dbaf1cff80f1c2fd940"
 //           .parse()
 //           .unwrap()
 //   );

    // The group wants to sign something!
    let message = "hello interwebz!";

    // Normally this should be sampled securely from a CSPRNG.
    // let mut nonce_seed = [0u8; 32]
    // rand::rngs::OsRng.fill_bytes(&mut nonce_seed);
    let nonce_seed = [0xACu8; 32];


    // This is how `FirstRound` derives the nonce internally.
    let mut secnonces = vec![];

    for i in 0..num_signers {
        let s = SecNonce::build(nonce_seed)
            .with_seckey(seckeys[i])
            .with_message(&message)
            .with_aggregated_pubkey(aggregated_pubkey)
            .with_extra_input(&(i as u32).to_be_bytes())
            .build();
        secnonces.push(s);
    }

    let public_nonces: Vec<PubNonce> = secnonces.iter().map(|s| s.public_nonce()).collect();

    //let our_public_nonce = secnonce.public_nonce();
    //assert_eq!(
    //    our_public_nonce,
    //    "02d1e90616ea78a612dddfe97de7b5e7e1ceef6e64b7bc23b922eae30fa2475cca\
    // 02e676a3af322965d53cc128597897ef4f84a8d8080b456e27836db70e5343a2bb"
    //        .parse()
    //        .unwrap()
    //);

    //// ...Exchange nonces with peers...

    //let public_nonces = [
    //    "02af252206259fc1bf588b1f847e15ac78fa840bfb06014cdbddcfcc0e5876f9c9\
    // 0380ab2fc9abe84ef42a8d87062d5094b9ab03f4150003a5449846744a49394e45"
    //        .parse::<PubNonce>()
    //        .unwrap(),
    //    "020ab52d58f00887d5082c41dc85fd0bd3aaa108c2c980e0337145ac7003c28812\
    // 03956ec5bd53023261e982ac0c6f5f2e4b6c1e14e9b1992fb62c9bdfcf5b27dc8d"
    //        .parse::<PubNonce>()
    //        .unwrap(),
    //    our_public_nonce,
    //];

    // We manually aggregate the nonces together and then construct our partial signature.
    let aggregated_nonce: AggNonce = public_nonces.iter().sum();
    let partial_signatures: Vec<PartialSignature> = secnonces
        .iter().enumerate()
        .map(|(i, s)| {
            musig2::sign_partial(&key_agg_ctx, seckeys[i], s.clone(), &aggregated_nonce, message)
                .expect("error creating partial signature")
        }).collect();
    //    let our_partial_signature: PartialSignature =
    //        musig2::sign_partial(&key_agg_ctx, seckey, secnonce, &aggregated_nonce, message)
    //            .expect("error creating partial signature");
    //
    //    let partial_signatures = [
    //        "5a476e0126583e9e0ceebb01a34bdd342c72eab92efbe8a1c7f07e793fd88f96"
    //            .parse::<PartialSignature>()
    //            .unwrap(),
    //        "45ac8a698fc9e82408367e28a2d257edf6fc49f14dcc8a98c43e9693e7265e7e"
    //            .parse::<PartialSignature>()
    //            .unwrap(),
    //        our_partial_signature,
    //    ];

    /// Signatures should be verified upon receipt and invalid signatures
    /// should be blamed on the signer who sent them.
    for (i, partial_signature) in partial_signatures.clone().into_iter().enumerate() {
   //     if i == signer_index {
   //         // Don't bother verifying our own signature
   //         continue;
   //     }

        let their_pubkey: PublicKey = key_agg_ctx.get_pubkey(i).unwrap();
        let their_pubnonce = &public_nonces[i];

        musig2::verify_partial(
            &key_agg_ctx,
            partial_signature,
            &aggregated_nonce,
            their_pubkey,
            their_pubnonce,
            message,
        )
        .expect("received invalid signature from a peer");
    }

    let final_signature: [u8; 64] = musig2::aggregate_partial_signatures(
        &key_agg_ctx,
        &aggregated_nonce,
        partial_signatures,
        message,
    )
    .expect("error aggregating signatures");

    //assert_eq!(
    //    final_signature,
    //    [
    //        0x38, 0xFB, 0xD8, 0x2D, 0x1D, 0x27, 0xBB, 0x34, 0x01, 0x04, 0x20, 0x62, 0xAC, 0xFD,
    //        0x4E, 0x7F, 0x54, 0xCE, 0x93, 0xDD, 0xF2, 0x6A, 0x4A, 0xE8, 0x7C, 0xF7, 0x15, 0x68,
    //        0xC1, 0xD4, 0xE8, 0xBB, 0x8F, 0xCA, 0x20, 0xBB, 0x6F, 0x7B, 0xCE, 0x2C, 0x5B, 0x54,
    //        0x57, 0x6D, 0x31, 0x5B, 0x21, 0xEA, 0xE3, 0x1A, 0x61, 0x46, 0x41, 0xAF, 0xD2, 0x27,
    //        0xCD, 0xA2, 0x21, 0xFD, 0x6B, 0x1C, 0x54, 0xEA
    //    ]
    //);

    musig2::verify_single(aggregated_pubkey, &final_signature, message)
        .expect("aggregated signature must be valid");
}
