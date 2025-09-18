## Vaults using blind co-signers

1) The holder wanting to deposit into a vault starts by contacting a set of
signer servers, to get their public keys and nonces.

Using this he creates a public key that is a Musig2 aggregate key of the
signers.

Using this key as the output, the client creates an unsigned transaction that
has this as its only output.

2) The signers are then asked to sign a spend tx from this output, spending the
full amount back to a recovery address. Together with this signing request, the
client attaches a ZK proof that proves that the recovery tx does exactly this
(spend whole amount into a hardcoded recovery address). This recovery address
is static for the whole vault lifetime, but not revealed to the signers.

Now that the client has this pre-signed spend transaction, it is safe to sign
the deposit tx and send the coins into the control of the signer quorum.

To unvault the funds, the owner will get a tweak the output aggregate key of 
the signers, and create an unvault tx that spends the funds to this public key.

Two spends from the unvault tx is created: one recovery tx and another spend tx
that is timelocked and spends the funds to the final destination. 

3) These txs and proof is sent to the signers who will validate that they are
indeed correctly crafted, then sign them.
