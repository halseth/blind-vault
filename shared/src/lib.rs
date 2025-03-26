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
    pub key_parity: u8,
    pub nonce_parity: u8,
    pub key_coeff: String,
    pub e: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignResp{
    pub session_id: String,
    pub sig: String,
}

