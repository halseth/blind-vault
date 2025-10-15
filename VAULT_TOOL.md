# Vault Management Tool

A unified command-line interface for managing Bitcoin vault operations using blind co-signers. This tool simplifies the entire vault lifecycle by integrating with bitcoind, the wallet tool, and the depositor/client components.

## Features

The `vault` script provides five main commands to manage your vault:

- **fund** - Deposit funds into a new vault with pre-signed recovery
- **unvault** - Initiate the unvault process with timelock protection
- **recover** - Trigger emergency recovery to the recovery address
- **finalize** - Complete the unvault after timelock expiration
- **status** - Display current vault state and next steps

## Prerequisites

1. **Required tools:**
   - `jq` - JSON processor for state management
   - `cargo` - Rust toolchain for building components
   - `bitcoin-cli` - Bitcoin Core RPC client

2. **Running services:**
   - Bitcoin Core node (signet/testnet/regtest)
   - Signer server(s) running on configured ports
   - Client server running and connected to signers

3. **Wallet setup:**
   ```bash
   cd wallet
   cargo run -- --new --network signet
   ```

## Quick Start

### 1. Start the required services

```bash
# Terminal 1: Start signer
cd signer/
cargo run -- --listen="127.0.0.1:8080"

# Terminal 2: Start client
cd client/
cargo run -- --listen 127.0.0.1:8090 --cfg '{"signers":["127.0.0.1:8080"]}' --network signet --static-fee "0.00001 BTC"
```

### 2. Fund your wallet address

```bash
# Get an address from your wallet
cd wallet
cargo run

# Fund it using bitcoin-cli or a faucet
bitcoin-cli -signet sendtoaddress <address> 0.001
```

### 3. Create a vault

```bash
./vault fund
```

This will:
- Select a UTXO from your wallet
- Prompt for a recovery address
- Create the vault with pre-signed recovery transaction
- Optionally broadcast the deposit transaction
- Save vault state to `vault-state.json`

### 4. Check vault status

```bash
./vault status
```

### 5. Initiate unvault

```bash
./vault unvault
```

This will:
- Prompt for destination address and timelock (in blocks)
- Create unvault, recovery, and final spend transactions
- Optionally broadcast the unvault transaction
- Track timelock progress

### 6. Wait for timelock and finalize

```bash
# Check remaining blocks
./vault status

# Once timelock expires, finalize
./vault finalize
```

## Command Reference

### `vault fund`

Creates a new vault deposit with pre-signed recovery.

**Interactive prompts:**
- Recovery address (where funds go in emergency)
- Whether to broadcast the deposit transaction

**What it does:**
1. Queries bitcoind for available UTXOs in your wallet
2. Selects the first available UTXO
3. Calls depositor to create vault with blind co-signers
4. Gets pre-signed recovery transaction
5. Signs and optionally broadcasts deposit transaction
6. Saves vault state

**Output:**
- Vault address (aggregated MuSig2 key)
- Deposit transaction details
- State saved to `vault-state.json`

### `vault unvault`

Initiates the unvault process to spend vault funds.

**Requirements:**
- Active vault in "funded" state

**Interactive prompts:**
- Destination address (final destination for funds)
- Timelock in blocks (delay before final spend)
- Whether to broadcast the unvault transaction

**What it does:**
1. Creates three transactions:
   - Unvault tx: Moves funds from vault to unvault output
   - Recovery tx: Pre-signed emergency recovery from unvault
   - Final spend tx: Timelocked spend to destination
2. Gets blind signatures from signers
3. Optionally broadcasts unvault transaction
4. Updates vault state to "unvaulted"

**Output:**
- Unvault transaction ID
- Unlock height (current height + timelock)
- All three transaction hex strings

### `vault recover`

Broadcasts the pre-signed recovery transaction.

**Requirements:**
- Active vault in "funded" or "unvaulted" state

**What it does:**
1. Identifies current vault stage
2. Selects appropriate recovery transaction:
   - From funded: Spends vault output to recovery address
   - From unvaulted: Spends unvault output to recovery address
3. Broadcasts recovery transaction
4. Updates vault state to "recovered"

**Use cases:**
- Emergency recovery if signers become unavailable
- Abort an unvault operation
- Move funds to secure cold storage

### `vault finalize`

Completes the unvault by broadcasting the final spend.

**Requirements:**
- Active vault in "unvaulted" state
- Current block height >= unlock height

**What it does:**
1. Checks if timelock has expired
2. Broadcasts the pre-signed final spend transaction
3. Updates vault state to "finalized"

**Output:**
- Final transaction ID
- Confirmation that funds are sent to destination

### `vault status`

Displays comprehensive vault information.

**Shows:**
- Vault ID (UTXO reference)
- Current status (funded/unvaulted/recovered/finalized)
- Vault address and recovery address
- Amount in BTC

**Additional info by state:**

**Funded:**
- Vault UTXO
- Next step: Run `vault unvault`

**Unvaulted:**
- Unvault UTXO
- Destination address
- Current vs unlock height
- Remaining blocks until timelock expires
- Next step: Wait or run `vault finalize`

**Recovered:**
- Recovery transaction ID
- Confirmation message

**Finalized:**
- Final spend transaction ID
- Destination address
- Completion message

## Configuration

The script uses environment variables for configuration:

```bash
# Network (signet, testnet, regtest)
export VAULT_NETWORK=signet

# Client server URL
export VAULT_CLIENT_URL=127.0.0.1:8090

# State file location
export VAULT_STATE_FILE=vault-state.json

# Bitcoin CLI command
export BITCOIN_CLI=bitcoin-cli

# Bitcoin CLI arguments
export BITCOIN_CLI_ARGS=-signet

# Static fee for transactions
export VAULT_STATIC_FEE="0.00001 BTC"
```

## State Management

The vault script maintains state in `vault-state.json` (or the path specified by `VAULT_STATE_FILE`).

**State file structure:**
```json
{
  "version": 1,
  "vaults": [
    {
      "id": "txid:vout",
      "status": "funded|unvaulted|recovered|finalized",
      "vault_utxo": {
        "txid": "...",
        "vout": 0,
        "amount": "0.001"
      },
      "vault_address": "tb1p...",
      "recovery_address": "tb1p...",
      "recovery_tx": "hex...",
      "deposit_tx": "hex...",
      "created_at": 1234567890,
      "unvault_txid": "...",
      "unvault_tx": "hex...",
      "unvault_recovery_tx": "hex...",
      "final_spend_tx": "hex...",
      "destination_address": "tb1p...",
      "timelock_blocks": 10,
      "unlock_height": 12345
    }
  ]
}
```

**State transitions:**
```
funded -> unvaulted -> finalized
   |          |
   v          v
recovered <- recovered
```

## Workflow Examples

### Example 1: Normal Vault Lifecycle

```bash
# 1. Create vault
./vault fund
# Enter recovery address: tb1p...recovery...
# Broadcast? y

# 2. Check status
./vault status
# Status: funded

# 3. Initiate unvault
./vault unvault
# Enter destination: tb1p...destination...
# Enter timelock: 10
# Broadcast? y

# 4. Wait for timelock
./vault status
# Remaining Blocks: 7

# ... wait for blocks ...

# 5. Finalize
./vault finalize
# Broadcast? y
# Status: finalized
```

### Example 2: Emergency Recovery

```bash
# 1. Create vault
./vault fund

# 2. Initiate unvault
./vault unvault

# 3. Emergency situation - recover immediately
./vault recover
# Broadcast? y
# Status: recovered
```

### Example 3: Testing Recovery Before Unvault

```bash
# 1. Create vault
./vault fund

# 2. Test recovery (abort before unvault)
./vault recover
# Funds returned to recovery address
```

## Integration with Bitcoin Core

The script uses `bitcoin-cli` to interact with Bitcoin Core:

**Query operations:**
- `listunspent` - Find UTXOs for funding
- `getblockcount` - Check timelock progress
- `getrawtransaction` - Verify transactions
- `decoderawtransaction` - Parse transaction details

**Broadcast operations:**
- `sendrawtransaction` - Broadcast signed transactions

**Configure your RPC connection:**
```bash
# For signet with authentication
export BITCOIN_CLI="bitcoin-cli"
export BITCOIN_CLI_ARGS="-signet -rpcuser=user -rpcpassword=pass"

# For testnet with cookie authentication
export BITCOIN_CLI_ARGS="-testnet"

# For regtest
export BITCOIN_CLI_ARGS="-regtest"
```

## Security Considerations

1. **Recovery address is permanent** - Choose carefully during `vault fund`
2. **Timelock cannot be changed** - Set appropriate duration during `vault unvault`
3. **State file contains sensitive data** - Contains all transaction hex
4. **Private keys stored in wallet.json** - The wallet tool stores keys in plaintext
5. **Pre-signed transactions are binding** - Recovery and final spend cannot be modified

## Troubleshooting

### "No keys found in wallet"
```bash
cd wallet
cargo run -- --new --network signet
```

### "No UTXOs found for address"
Fund the wallet address:
```bash
bitcoin-cli -signet sendtoaddress <address> 0.001
```

### "Client connection refused"
Ensure client server is running:
```bash
cd client
cargo run -- --listen 127.0.0.1:8090 --cfg '{"signers":["127.0.0.1:8080"]}' --network signet --static-fee "0.00001 BTC"
```

### "Timelock not yet expired"
Check remaining blocks:
```bash
./vault status
```
Wait for more blocks to be mined.

### "Failed to create vault deposit"
Check that:
1. Signer server is running
2. Client server is running and connected to signer
3. Network matches across all components
4. Recovery address is valid for the network

## Advanced Usage

### Multiple Vaults

The script tracks all vaults in the state file. Active vault is the most recent non-finalized/non-recovered vault.

```bash
# View all vaults
./vault status
```

### Custom State File

```bash
VAULT_STATE_FILE=my-vault.json ./vault fund
VAULT_STATE_FILE=my-vault.json ./vault status
```

### Mainnet Warning

The wallet tool is NOT secure and explicitly blocks mainnet usage. For mainnet vaults:
1. Use proper key management (hardware wallet)
2. Modify depositor to use secure signing
3. Never use wallet tool on mainnet

## Architecture

```
┌──────────┐
│  vault   │  Bash script (this tool)
└────┬─────┘
     │
     ├─────> bitcoin-cli (query UTXOs, broadcast txs)
     │
     ├─────> wallet (key management)
     │       └─> wallet.json
     │
     ├─────> depositor (create vault, unvault operations)
     │       └─> client (coordinator)
     │           └─> signer (blind co-signer)
     │
     └─────> vault-state.json (state tracking)
```

## See Also

- [CLAUDE.md](CLAUDE.md) - Project overview
- [doc/vault.md](doc/vault.md) - Vault protocol design
- [wallet/README.md](wallet/README.md) - Wallet tool documentation
