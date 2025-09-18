# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust implementation of a Bitcoin vault system using blind co-signers. The system enables secure Bitcoin storage through multi-signature schemes with privacy-preserving blind signing protocols, following the design outlined in `doc/vault.md`. The architecture consists of three main components that work together to create secure vault deposits and controlled withdrawals with pre-signed recovery mechanisms.

## Commands

### Building and Running

Each component is a separate Rust crate that must be built and run independently:

```bash
# Build all components
cargo build

# Build specific component
cd [client|signer|depositor|shared]
cargo build

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy linter
cargo clippy
```

### Running the System

The system requires running components in this specific order:

1. **Start the signer server:**
```bash
cd signer/
cargo run -- --listen="127.0.0.1:8080"
```

2. **Start the client server:**
```bash
cd client/
cargo run -- --listen 127.0.0.1:8090 --cfg '{"signers":["127.0.0.1:8080"]}' --server
```

3. **Run a vault deposit operation:**
```bash
cd depositor/
cargo run -- --prevout "e5a1bdd3f3318e6d27f5f61ec95831998f73a98640a69c87304230a58ea02e32:262" --prev-amt "0.00190943 BTC" --output-amt "0.0019 BTC" --client-url "127.0.0.1:8090" --priv-key "8c99b79db6e36fa099b0368408bf630fbe8bc271c639b32d5bcce609fdc07f3f" --fallback-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3" --recovery-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3"
```

## Architecture

### Component Structure

- **shared/**: Common data structures and protocol messages used across components
- **signer/**: HTTP server that provides blind signing services for vault operations
- **client/**: Orchestrates the signing process between depositors and signers
- **depositor/**: Creates deposit transactions and handles the deposit flow
- **src/main.rs**: Standalone test/example code demonstrating MuSig2 operations

### Key Technologies

- **MuSig2**: Multi-signature scheme for Bitcoin transactions using Schnorr signatures
- **Blind Signatures**: Privacy-preserving signature protocol where signers don't see the actual transaction data
- **PSBT (Partially Signed Bitcoin Transactions)**: Bitcoin transaction format for multi-party signing
- **Zero-Knowledge Proofs**: Used to prove transaction validity without revealing transaction details

### Protocol Flow

The vault system implements a two-phase protocol as described in `doc/vault.md`:

1. **Vault Deposit Phase**:
   - Depositor creates unsigned deposit PSBT
   - Client coordinates with signers to get public keys and nonces
   - Client creates MuSig2 aggregated vault public key from signers
   - Client constructs recovery transaction (vault → recovery address)
   - Signers verify ZK proof and blind-sign recovery transaction
   - Depositor signs and broadcasts deposit transaction (now safe with pre-signed recovery)

2. **Vault Unvault Phase**:
   - Client gets fresh keys/nonces from signers for new aggregated key
   - Client creates unvault transaction with timelock + script fallback paths
   - Client creates final spend transaction (timelocked)
   - Signers verify ZK proofs and blind-sign both transactions
   - Client broadcasts unvault tx, waits for timelock, then broadcasts final spend

### API Endpoints

**Client endpoints:**
- `POST /vault/deposit` - Initiates vault deposit flow
- `POST /vault/unvault` - Initiates vault unvault flow  
- `POST /psbt` - Legacy PSBT signing (for backward compatibility)

**Signer endpoints:**
- `GET /init/{session_id}` - Initialize signing session
- `POST /sign/{session_id}` - Sign with transaction type validation (includes `tx_type` field)
- `POST /vault/recovery/{session_id}` - Sign recovery transactions (uses ZK proofs)
- `POST /vault/unvault/{session_id}` - Sign unvault transactions (uses ZK proofs)

### Transaction Types

The signer now validates different transaction types in the signing process:

- **RECOVERY**: Pre-signed recovery transactions that spend to committed recovery address
- **VAULT**: Initial vault deposit transactions using aggregated keys
- **UNVAULT**: Unvault transactions with timelock and script fallback paths  
- **FINAL**: Timelocked final spend transactions (can reuse UNVAULT session)

Each session tracks its usage and enforces single-use constraints except for FINAL transactions which can follow UNVAULT.

### Dependencies

The project uses custom Bitcoin and MuSig2 library forks:
- `bitcoin`: Custom fork at `halseth/rust-bitcoin` (rev: da1d657)
- `musig2`: Custom fork at `halseth/musig2` (rev: 47fe67f)
- Standard cryptographic libraries: `secp256k1`, `sha2`, `k256`
- Web framework: `actix-web` for HTTP servers
- HTTP client: `reqwest` for inter-service communication

### Testing

Each component can be tested independently with `cargo test`. The main entry point (`src/main.rs`) contains extensive test code demonstrating the cryptographic primitives.

## Important Notes

- This is experimental cryptographic software implementing a Bitcoin vault system
- The system uses custom forks of Bitcoin libraries - ensure compatibility when updating dependencies
- All components must use the same cryptographic parameters and protocol versions
- ZK proof generation/verification is handled by external tools (assumed to be available)
- The current implementation includes placeholder logic for some complex operations
- Private keys and sensitive data should be handled securely in production environments
- Recovery mechanisms are critical - ensure recovery addresses are properly secured