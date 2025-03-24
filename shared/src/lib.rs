use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct InitResp {
    pub id: String,
    pub pubkey: String,
    pub pubnonce: String,
}
