# Ephemeral-sign

## Usage

### 1. Start the signer

```bash
$ cd signer/
$ cargo run -- --listen="127.0.0.1:8080"
```

### 2. Start the client:
```bash
$ cd client/
$ cargo run -- --listen 127.0.0.1:8090 --cfg '{"signers":["127.0.0.1:8080"]}' --server
```

### 3. Run the depositor:
```bash
$ cd depositor/
$ cargo run -- --prevout "e5a1bdd3f3318e6d27f5f61ec95831998f73a98640a69c87304230a58ea02e32:262" --prev-amt "0.00190943 BTC" --output-amt "0.0019 BTC" --client-url "127.0.0.1:8090" --priv-key "8c99b79db6e36fa099b0368408bf630fbe8bc271c639b32d5bcce609fdc07f3f" --fallback-addr "tb1ptsxxhp5j8umn2pm47dldpfa3zkke2eshtfc6car7x8tfhtgnmqpsrx0ae3"
```

## Explanation

When the depositor is run a deposit PSBT transaction is made that to a yet to be determined public key. This PSBT is
then sent to the client for further handling.

The client receives the deposit tx, and contacts all the signers in order to receive a fresh public key and nonces from
each. The client uses this information to assemble the output public key of the deposit tx.

Now that the client has assembled the full deposit transaction (except from signature), it assembles a transaction that
spends from the deposit tx.

The sighash of the spend transaction is blinded and sent to the signers, which will sign.

The client can now assemble the final spend and send it together with the deposit tx back to the depositor.

The depositor can now verify that the spend is correctly spending the deposit transaction, before signing the deposit
and broadcasting it.

