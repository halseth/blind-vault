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
    pub b: String,
    pub e: String,
    pub tx_type: String,
    pub zk_proof: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignResp {
    pub session_id: String,
    pub sig: String,
}

// Vault deposit flow types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultDepositReq {
    pub deposit_psbt: Psbt,
    pub recovery_addr: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultDepositResp {
    pub deposit_psbt: Psbt,
    pub recovery_psbt: Psbt,
    pub vault_pubkey: String,
}


// Vault unvault flow types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultUnvaultReq {
    pub vault_outpoint: String,
    pub destination_addr: String,
    pub amount: u64,
    pub timelock_blocks: u32,
    pub recovery_addr: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultUnvaultResp {
    pub unvault_psbt: Psbt,
    pub recovery_psbt: Psbt,
    pub final_spend_psbt: Psbt,
    pub unvault_pubkey: String,
}


