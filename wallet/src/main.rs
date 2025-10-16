use bitcoin::address::script_pubkey::ScriptBufExt;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::witness::WitnessExt;
use bitcoin::{consensus, Address, Network, PrivateKey, Psbt, ScriptBuf};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const WALLET_FILE: &str = "wallet.json";

#[derive(Debug, Parser)]
#[command(name = "wallet")]
#[command(about = "Simple Bitcoin wallet for key management and signing", long_about = None)]
struct Args {
    /// Generate a new keypair and add it to the wallet
    #[arg(long)]
    new: bool,

    /// Sign a PSBT with a key from the wallet
    #[arg(long)]
    sign: bool,

    /// Key identifier (public key or address) to use for signing
    #[arg(long, required_if_eq("sign", "true"))]
    key: Option<String>,

    /// PSBT in hex format to sign
    #[arg(long, required_if_eq("sign", "true"))]
    psbt: Option<String>,

    /// Bitcoin network (signet, testnet, regtest) - mainnet is DISABLED for security
    #[arg(long, default_value = "signet")]
    network: Network,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletData {
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct KeyEntry {
    private_key: String,
    public_key: String,
    address: String,
    #[serde(default = "default_network")]
    network: String,
}

fn default_network() -> String {
    "signet".to_string()
}

impl WalletData {
    fn new() -> Self {
        WalletData { keys: Vec::new() }
    }

    fn load() -> Self {
        if Path::new(WALLET_FILE).exists() {
            let data = fs::read_to_string(WALLET_FILE).expect("Failed to read wallet file");
            serde_json::from_str(&data).expect("Failed to parse wallet file")
        } else {
            WalletData::new()
        }
    }

    fn save(&self) {
        let json = serde_json::to_string_pretty(self).expect("Failed to serialize wallet");
        fs::write(WALLET_FILE, json).expect("Failed to write wallet file");
    }

    fn add_key(&mut self, entry: KeyEntry) {
        self.keys.push(entry);
    }

    fn find_key(&self, identifier: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|entry| {
            entry.public_key == identifier || entry.address == identifier
        })
    }
}

fn generate_keypair(network: Network) -> KeyEntry {
    let secp = Secp256k1::new();
    let sk = SecretKey::new(&mut rand::thread_rng());
    let keypair = Keypair::from_secret_key(&secp, &sk);

    let (xonly_pubkey, _parity) = keypair.x_only_public_key();
    let script_buf = ScriptBuf::new_p2tr(&secp, xonly_pubkey, None);
    let address = Address::from_script(script_buf.as_script(), network)
        .expect("Failed to create address");

    KeyEntry {
        private_key: hex::encode(keypair.secret_key().secret_bytes()),
        public_key: xonly_pubkey.to_string(),
        address: address.to_string(),
        network: network.to_string(),
    }
}

fn display_keys(wallet: &WalletData, _network: Network) {
    if wallet.keys.is_empty() {
        println!("No keys in wallet. Use --new to generate a key.");
        return;
    }

    println!("Wallet keys:");
    println!("{}", "-".repeat(80));
    for (i, entry) in wallet.keys.iter().enumerate() {
        println!("Key #{}:", i + 1);
        println!("  Private key: {}", entry.private_key);
        println!("  Public key:  {}", entry.public_key);
        println!("  Address:     {}", entry.address);
        println!("  Network:     {}", entry.network);
        println!();
    }
}

fn sign_psbt(wallet: &WalletData, key_id: &str, psbt_hex: &str, network: Network) {
    // Find the key
    let key_entry = wallet
        .find_key(key_id)
        .expect("Key not found in wallet");

    // Parse PSBT
    let mut psbt: Psbt = Psbt::deserialize(&hex::decode(psbt_hex).expect("Invalid PSBT hex"))
        .expect("Failed to deserialize PSBT");

    // Create secp context
    let secp = Secp256k1::new();

    // Parse private key
    let sk_bytes = hex::decode(&key_entry.private_key).expect("Invalid private key hex");
    let sk = SecretKey::from_slice(&sk_bytes).expect("Invalid secret key");
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (xonly_pubkey, _) = keypair.x_only_public_key();

    // Create key map for signing
    let mut key_map: HashMap<bitcoin::XOnlyPublicKey, PrivateKey> = HashMap::new();
    let priv_key = PrivateKey::new(sk, network);
    key_map.insert(xonly_pubkey, priv_key);

    // Sign the PSBT
    psbt.sign(&key_map, &secp).expect("Failed to sign PSBT");

    // Finalize the PSBT
    psbt.inputs.iter_mut().for_each(|input| {
        if let Some(tap_key_sig) = input.tap_key_sig {
            let script_witness = bitcoin::Witness::p2tr_key_spend(&tap_key_sig);
            input.final_script_witness = Some(script_witness);

            // Clear all the data fields as per the spec
            input.partial_sigs = std::collections::BTreeMap::new();
            input.sighash_type = None;
            input.redeem_script = None;
            input.witness_script = None;
            input.bip32_derivation = std::collections::BTreeMap::new();
        }
    });

    // Extract the signed transaction
    let signed_tx = psbt.extract_tx().expect("Failed to extract transaction");
    let signed_tx_hex = hex::encode(consensus::encode::serialize(&signed_tx));

    println!("Signed transaction:");
    println!("{}", signed_tx_hex);
}

fn main() {
    let args = Args::parse();

    // WARNING: This tool is for testing/development only
    if args.network == Network::Bitcoin {
        eprintln!("ERROR: This wallet tool is NOT secure and must NOT be used on mainnet!");
        eprintln!("It stores private keys in plaintext and lacks proper security measures.");
        eprintln!("Use only on signet, testnet, or regtest.");
        std::process::exit(1);
    }

    if args.new {
        // Generate new key
        let mut wallet = WalletData::load();
        let entry = generate_keypair(args.network);

        println!("Generated new key:");
        println!("  Private key: {}", entry.private_key);
        println!("  Public key:  {}", entry.public_key);
        println!("  Address:     {}", entry.address);
        println!("  Network:     {}", entry.network);

        wallet.add_key(entry);
        wallet.save();
        println!("\nKey saved to {}", WALLET_FILE);
    } else if args.sign {
        // Sign PSBT
        let wallet = WalletData::load();
        let key_id = args.key.expect("--key is required for signing");
        let psbt_hex = args.psbt.expect("--psbt is required for signing");

        sign_psbt(&wallet, &key_id, &psbt_hex, args.network);
    } else {
        // List keys (default behavior)
        let wallet = WalletData::load();
        display_keys(&wallet, args.network);
    }
}
