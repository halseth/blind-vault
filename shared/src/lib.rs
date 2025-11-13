use bitcoin::Psbt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InitReq {
    pub timelock_commitment: String, // Hex-encoded SHA256(salt || nSequence), supports block-height and time-based timelocks
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InitResp {
    pub session_id: String,
    pub pubkey: String,
    pub pubnonces: Vec<String>,
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
    pub nsequence_proof: Option<String>,  // JSON-encoded ZK proof from zk-tx for nSequence verification
    pub message_salt: Option<String>,     // Hex-encoded 32-byte salt for message commitment verification
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
    pub timelock_blocks: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultDepositResp {
    pub deposit_psbt: Psbt,
    pub vault_recovery_psbt: Psbt,
    pub unvault_recovery_psbt: Psbt,
    pub vault_address: String,
    pub session_data: VaultSessionData,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultSessionData {
    pub session_ids: Vec<String>,
    pub coeff_salt: String,
    pub pubkeys: Vec<String>,
    pub pubnonces: Vec<Vec<String>>,  // Outer vec: per signer, Inner vec: per nonce (now 4)
    pub timelock_blocks: u32,
    pub timelock_salts: Vec<String>,  // Per-signer salts for timelock commitment proofs (hex-encoded)
    pub message_salts: Vec<String>,    // Per-signer salts for message commitment proofs (hex-encoded)
    pub recovery_addr: String,
}


// Vault unvault flow types
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultUnvaultReq {
    pub vault_outpoint: String,
    pub destination_addr: String,
    pub amount: u64,
    pub recovery_addr: String,
    pub session_data: VaultSessionData,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultUnvaultResp {
    pub unvault_psbt: Psbt,
    pub final_spend_psbt: Psbt,
    pub unvault_pubkey: String,
}


