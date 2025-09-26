# Bitcoin Vault System with Blind Co-Signers

This is a Rust implementation of a Bitcoin vault system using blind co-signers that enables secure Bitcoin storage through multi-signature schemes with privacy-preserving blind signing protocols.

## Usage

### 1. Start the signer

```bash
$ cd signer/
$ cargo run -- --listen="127.0.0.1:8080" --priv-key="c28a9f80738efe7b628cc2b68d7f8d2d6b5633ce8b0f3e7d3b6d8a9f8e2b9c1d"
```

### 2. Start the client:
```bash
$ cd client/
$ cargo run -- --listen 127.0.0.1:8090 --cfg '{"signers":["127.0.0.1:8080"]}' --server
```

### 3. Create a vault deposit:
```bash
$ cd depositor/
$ cargo run -- create --prevout "e5a1bdd3f3318e6d27f5f61ec95831998f73a98640a69c87304230a58ea02e32:262" --prev-amt "0.00190943 BTC" --output-amt "0.0019 BTC" --client-url "127.0.0.1:8090" --priv-key "8c99b79db6e36fa099b0368408bf630fbe8bc271c639b32d5bcce609fdc07f3f" --fallback-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3" --recovery-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3"
```

### 4. Unvault funds from a vault:
```bash
$ cd depositor/
$ cargo run -- unvault --vault-outpoint "e5a1bdd3f3318e6d27f5f61ec95831998f73a98640a69c87304230a58ea02e32:0" --vault-amount "0.001 BTC" --destination-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3" --timelock-blocks 144 --recovery-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3" --client-url "127.0.0.1:8090"
```

## How It Works

### Vault Deposit Flow

1. **Depositor** creates a deposit PSBT transaction to a yet-to-be-determined public key and sends it to the client
2. **Client** contacts all signers to receive fresh public keys and nonces, then assembles the aggregated vault public key
3. **Client** creates a recovery transaction spending from the deposit to the recovery address
4. **Signers** verify ZK proofs and blind-sign the recovery transaction using the "RECOVERY" transaction type
5. **Depositor** receives the signed deposit PSBT and pre-signed recovery transaction, verifies them, then signs and broadcasts the deposit

### Vault Unvault Flow

1. **Depositor** initiates unvault with vault outpoint, destination address, recovery address, and timelock period
2. **Client** generates the same aggregated public key as the original vault deposit
3. **Client** creates three transactions:
   - **Unvault transaction**: Spends vault output to new output with same aggregated key
   - **Recovery transaction**: Spends unvault output to recovery address (immediate)
   - **Sweep transaction**: Spends unvault output to destination address (timelocked)
4. **Signers** verify ZK proofs and blind-sign all three transactions using "UNVAULT" and "FINAL" transaction types
5. **Depositor** receives all three pre-signed transactions and can broadcast them as needed:
   - Broadcast unvault transaction to start the unvault process
   - Either broadcast recovery transaction immediately, or wait for timelock and broadcast sweep transaction

### Security Model

- **Privacy**: Signers cannot see the actual transaction data due to blind signatures
- **Safety**: Pre-signed recovery transactions ensure funds can always be recovered
- **Flexibility**: Timelock allows for delayed final spending while maintaining immediate recovery option
- **Verification**: ZK proofs ensure transaction validity without revealing sensitive information

