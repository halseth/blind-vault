use bitcoin::Psbt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InitResp {
    pub session_id: String,
    pub pubkey: String,
    pub pubnonce: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignReq {
    pub session_id: String,
    pub challenge_parity: u8,
    pub nonce_parity: u8,
    pub key_coeff: String,
    pub e: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignResp {
    pub session_id: String,
    pub sig: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignPsbtReq {
    pub psbt: Psbt,
    pub fallback_addr: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignPsbtResp {
    pub deposit_psbt: Psbt,
    pub spend_psbt: Psbt,
}
