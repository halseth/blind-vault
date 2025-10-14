# Wallet - Simple Bitcoin Key Management Tool

⚠️ **WARNING: FOR TESTING/DEVELOPMENT ONLY** ⚠️

**DO NOT USE ON MAINNET!** This tool:
- Stores private keys in **plaintext** JSON files
- Has **no encryption** or security measures
- Is designed **only for testing** on signet, testnet, or regtest
- Will **refuse to run** if mainnet network is specified

This is a development tool for the blind-vault project. Never use it with real Bitcoin.

## Features

### List Keys (default)
Display all stored keys with private key, public key, and taproot address:
```bash
cargo run
```

### Generate New Key
Create a new keypair and save to wallet.json:
```bash
cargo run -- --new
```

### Sign PSBT
Sign a PSBT with a key from the wallet (identified by pubkey or address):
```bash
cargo run -- --sign --key <PUBKEY_OR_ADDRESS> --psbt <HEX_ENCODED_PSBT>
```

### Network Selection
Specify the network (default: signet):
```bash
cargo run -- --network testnet
cargo run -- --network regtest
cargo run -- --network signet  # default
```

**Note:** Mainnet (--network bitcoin) is explicitly disabled for safety.

## Storage

Keys are stored in `wallet.json` in the current working directory in the following format:

```json
{
  "keys": [
    {
      "private_key": "hex_encoded_private_key",
      "public_key": "x_only_public_key",
      "address": "tb1p..."
    }
  ]
}
```

## Security Notice

This tool is intentionally simple and insecure. It is meant for:
- Local testing and development
- Generating test keys quickly
- Signing test transactions

For production use, always use proper wallet software with:
- Hardware wallet support
- Key encryption
- Proper key derivation (BIP32/39/44)
- Multi-signature schemes
- Secure key storage
