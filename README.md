# Bitcoin Vault System with Blind Co-Signers

This is a Proof-of-Concept implementation of a Bitcoin vault system using blind 
co-signers to enable unvault and recovery mechanismsm wihout a covenant. 

The use of a blinded variant of the Musig2 multi-signature scheme helps
preserving the privacy of the vault user both in terms of on-chain and
co-signer fingerprint.

NOTE: this project is considered a prototype and should not be used with real
funds.

## Prerequisites

Before using this system, ensure you have the following tools installed:

1. **Zero-Knowledge Proof Tools** (required for vault operations):

    [zk-musig](https://github.com/halseth/zk-musig)
   ```bash
   # Install zk-musig for MuSig2 signature proofs
   cargo install --path /path/to/zk-musig/host
   ```

    [zk-tx](https://github.com/halseth/zk-tx)
   ```bash
   # Install zk-tx for transaction property proofs
   cargo install --path /path/to/zk-tx/host
   ```

2. **Development Mode** (for testing and development):
   ```bash
   # Set RISC0_DEV_MODE to use faster, non-production proofs
   export RISC0_DEV_MODE=1
   ```

   **Note**: `RISC0_DEV_MODE=1` disables cryptographic proof generation for
   faster development. Only use this for testing, never in any kind of
   production setting.

## Usage

### Complete Example: Fund, Deposit, and Unvault

This example walks through the full flow using the wallet tool to manage keys
and fund a UTXO on signet.

#### 0. Generate a key and fund it on signet

```bash
$ cd wallet/
# Generate a new key (signet is the default)
$ cargo run -- --new --network signet
Generated new key:
  Private key: 8c99b79db6e36fa099b0368408bf630fbe8bc271c639b32d5bcce609fdc07f3f
  Public key:  a1b2c3d4...
  Address:     tb1p...

# Fund this address on signet using a faucet, then note the transaction:
# - txid: e5a1bdd3f3318e6d27f5f61ec95831998f73a98640a69c87304230a58ea02e32
# - vout: 0
# - amount: 0.00190943 BTC
```

#### 1. Start the signer

```bash
$ cd signer/
$ cargo run --release -- --listen="127.0.0.1:8080" --priv-key="c28a9f80738efe7b628cc2b68d7f8d2d6b5633ce8b0f3e7d3b6d8a9f8e2b9c1d"
```

#### 2. Start the client

First create a config file `client-config.json`:
```json
{
  "signers": ["127.0.0.1:8080"],
  "network": "signet",
  "static_fee": "0.00000500 BTC"
}
```

Then start the client:
```bash
$ cd client/
$ cargo run --release -- --listen 127.0.0.1:8090 --cfg client-config.json
```

#### 3. Create a vault deposit

Use the funded UTXO from step 0:

```bash
$ cd depositor/
$ cargo run -- create \
  --prevout "e5a1bdd3f3318e6d27f5f61ec95831998f73a98640a69c87304230a58ea02e32:0" \
  --prev-amt "0.00190943 BTC" \
  --output-amt "0.0019 BTC" \
  --timelock-blocks 144 \
  --client-url "127.0.0.1:8090" \
  --priv-key "8c99b79db6e36fa099b0368408bf630fbe8bc271c639b32d5bcce609fdc07f3f" \
  --recovery-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3"

# This outputs:
# - Raw deposit transaction (broadcast this to create the vault)
# - Raw recovery transaction (pre-signed, can be used if needed)
# - Vault address (the aggregated multisig address)
# - Session data (JSON, save this for unvaulting later)
```

#### 4. Unvault funds from a vault

After broadcasting the deposit transaction, use the vault outpoint:

```bash
$ cd depositor/
$ cargo run -- unvault \
  --vault-outpoint "<deposit_txid>:0" \
  --vault-amount "0.0019 BTC" \
  --destination-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3" \
  --recovery-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3" \
  --session-data '<session_data_json_from_create>' \
  --client-url "127.0.0.1:8090"
```

Note: The `session_data` is the JSON output from the create command and
contains the aggregated public key and other session information needed to
reconstruct the vault.

## How It Works

### Vault Deposit Flow

1. **Depositor** creates a deposit PSBT transaction to a yet-to-be-determined
   public key and sends it to the client, and sets vault parameters like
   recovery address and unvault grace period.
2. **Client** contacts all signers to receive fresh public keys and nonces,
   then assembles the aggregated vault public key
3. **Client** creates a recovery transaction spending from the deposit to the
   recovery address, an unvault transaction spending from the deposit to a
   new aggregate public key, and a recovery transcation spending from
   this new key to the recovery address.
4. **Signers** blind-sign the vault recovery, unvault and unvault recovery
   transactions 
5. **Depositor** receives the signed deposit PSBT and pre-signed vault
   recovery, unvault and unvault recovery transactions, verifies them, then
   signs and broadcasts the deposit

### Vault Unvault Flow

1. **Depositor** initiates unvault to a destination address.
2. **Client** generates a timelocked finalization tx that spends the unvault
   output to the final destination.
3. **Client** creates a ZK proof proving to the signers that the transaction is
   timelocked according to the vault policy.
4. **Signers** verify ZK proofs and blind-sign the finalization tx.
5. **Depositor** receives the finalization tx, verifies it and broadcast the
   unvault tx.
6. **Depositor** braodcasts final tx when timelock has expired.

### Security Model

- **Privacy**: Signers cannot see the actual transaction data due to blind
  signatures
- **Safety**: Pre-signed recovery transactions ensure funds can always be
  recovered
- **Flexibility**: Relative timelock (nSequence) allows for delayed final
  spending while maintaining immediate recovery option
- **Verification**: ZK proofs ensure transaction validity without revealing
  sensitive information:
  - **MuSig2 proofs**: Verify signature aggregation and commitment structure
  - **nSequence proofs**: Verify relative timelocks on final spend transactions
  - **Message commitment binding**: Ensures consistency between MuSig2 and
    nSequence proofs

