## Vaults using blind co-signers
The holder wanting to deposit into a vault starts by contacting a set of signer
servers, to get their public keys and nonces.

Using this he creates a public key that is a Musig2 aggregate key of the
signers.

Using this key as the output, the client creates an unsigned transaction that
has this as its only output.

The signers are then asked to sign a spend tx from this output, spending the
full amount back to a recovery address. Together with this signing request, the
client attaches a ZK proof that proves that the recovery tx does exactly this
(spend whole amount into a hardcoded recovery address).

Now that the client has this pre-signed spend transaction, it is safe to sign
the deposit tx and send the coins into the control of he signer quorum.

To unvault the funds, the owner will get a fresh set of keys and nonces from
the signers, and create an unvault tx that spends the funds to this public key,
along with a script path that spends it all back to the recovery address. This
tx (or the sign request) must commit to the final destination of the funds.

Another spend tx is then created, that is timelocked and spends the funds to
the final destination. This tx and proof is sent to the signers who will
validate that the tx is indeed correctly crafted, then sign it.

The unvault tx is then sent as a sign request to the signers along with a ZK
proof. This proof must prove that the spend is to an output that has a
timelocked script path, and that the output key is correct.

