## Vaults using blind co-signers

### Background
Consult [Blinded Musig2](https://github.com/halseth/ephemeral-signing-service/blob/main/doc/general.md)
for background on the blinded signature scheme.

## Introduction

Vaults are a much sought after feature in Bitcoin that many believe finally
would make safe self-custody practical for the regular Joe.

A construction that is possible on Bitcoin today is using a co-signer together
with some sort of second-factor authemntication and transaction policy to
emulate vault-like behaviour. This is a secure and user-friendly setup that is
deployed successfully by many of the largest custodians today.

The main drawback with this setup is that the co-signer gains perfect insight
into the users transactional activity, policy and holdings. Depending on the
setup, the co-signer might also have the ability to freeze the users funds or
making them inaccessible in case of bankcrupty.

In this post we aim to mitigate these problems by outsourcing the signing to
semi-trusted signing servers, eliminating any single points of failure by
having them engage in a blinded multi-signature protocol scheme. 

In order to ensure that blinded messages are well-formed, and that encoding a
transaction policy the signers can enforce without giving up privacy,
zero-knowledge proofs will play a key role.

## Setup
The protocol will involve these actors:
- **Depositor**: the software or hardware entity controlling the keys to the
  coins that are to be deposited into the vault.
- **Client**: the aggregation software that is responsible for building the
  transaction graph, communicating with the signers and deriving blinding
  factors.
- **Signer**: Semi-trusted software agent that will blindly sign messages sent
  by the client using a key they control. It can also enforce transaction
  policies using a ZK verifier agreed on when the vault us first created.

```mermaid
  graph TD;
      Depositor<-->Client;
      Client<-->Signer1;
      Client<-->Signer2;
```

## High-level protocol overview
With a blinded signing scheme in place we can build a safe and practical vault
implementation by passing PSBTs around.

1. The depositor creates a PSBT specifying inputs for the deposit transaction,
   as well as the amount for the vault output and any change outputs.

2. The PSBT is sent to the client which sets up signing sessions with the
   signers.

3. Using the public keys of the signers, the client creates the aggregate
   public key that funds will be sent to.

4. The client builds the vault recovery transaction that will spend from the
   aggregate public key back to the recovery address.

5. The client generates a second aggregate public key for the unvault output
   and deterministically constructs the unvault transaction to predict its txid.

6. Using the predicted unvault txid, the client builds the unvault recovery
   transaction that will spend from the unvault output back to the recovery
   address.

7. The client sends blinded variants of both recovery transactions to the
   signers along with ZK proofs.

8. Each signer will respond with partial signatures for both recovery
   transactions using different nonces for each.

9. The client verifies that both recovery transactions are valid and fully
   signed.

10. The depositor receives the final PSBT with the vault output key filled and
    both pre-signed recovery transactions from the client. It can now sign the
    deposit and move the funds to the vault, knowing it has recovery options
    for both the vault and unvault states.


### Details

1) The holder wanting to deposit into a vault starts by contacting a set of
signer servers, to get their public keys and nonces.

Using this he creates a public key that is a Musig2 aggregate key of the
signers.

Using this key as the output, the client creates an unsigned transaction that
has this as its only output.

2) The signers are then asked to sign TWO recovery transactions from the vault:

   a) **Vault recovery tx**: Spends from the vault output back to the recovery
      address. Together with this signing request, the client attaches a ZK
      proof that proves the transaction spends the whole amount to the hardcoded
      recovery address.

   b) **Unvault recovery tx**: To create this, the client first generates a
      second aggregate public key (using fresh nonces from the signers) and
      deterministically constructs the unvault transaction. By predicting the
      unvault txid, the client can build a recovery transaction that spends from
      the unvault output back to the recovery address. A ZK proof is attached
      proving this transaction is correctly formed.

   The recovery address is static for the whole vault lifetime, but not revealed
   to the signers. Each signer uses a different nonce for each recovery
   transaction.

   Now that the client has BOTH pre-signed recovery transactions, it is safe to
   sign the deposit tx and send the coins into the control of the signer quorum.
   This protects against a compromised client during the unvault phase, as the
   depositor already holds a pre-signed recovery transaction for the unvault
   state.

3) To unvault the funds, the owner contacts the client which uses the same
   session data (public keys, nonces, coefficient salt) from vault creation to
   reconstruct the same unvault aggregate key. The client creates:

   a) **Unvault tx**: Spends from the vault to the pre-determined unvault output

   b) **Final spend tx**: Timelocked transaction that spends from the unvault
      output to the final destination

   Note that the unvault recovery tx is NOT created at this point - it was
   already pre-signed during vault creation (step 2b).

4) These txs and proofs are sent to the signers who validate they are correctly
   crafted, then sign them using the remaining nonces from the original session.

### Nonce Management

To enable pre-signing both recovery transactions during vault creation while
still allowing the unvault and final spend transactions to be signed later, each
signer generates **4 nonces** per vault session:

- **Nonce 0**: Used for signing the vault recovery transaction (during vault creation)
- **Nonce 1**: Used for signing the unvault recovery transaction (during vault creation)
- **Nonce 2**: Used for signing the unvault transaction (during unvault phase)
- **Nonce 3**: Used for signing the final spend transaction (during unvault phase)

All nonces are generated during the initial vault creation and stored in the
session data. The client reuses the same session (including public keys, nonces,
and coefficient salt) during the unvault phase to ensure the unvault aggregate
key matches the predicted value used when pre-signing the unvault recovery
transaction.

This nonce allocation ensures that:
1. Both recovery transactions can be pre-signed before the deposit is made
2. The depositor holds complete recovery options before funds enter the vault
3. The same session can be safely reused for the unvault operations without
   nonce reuse vulnerabilities
