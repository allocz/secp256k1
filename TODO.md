Improve schnorr tests by setting error kinds

C implementation: zero out allocations of:
* SchnorrVerify

Would be nice to PublicKeyFromBytes work with
* 32 byte X only pubkey with even Y
* 64 byte XY pubkey
* 33 byte compressed pubkey

Add ECDSASignatureFromDERBytes(sigOut, data, lax bool)

Add PrivateKey.ToBytes()
Add PublicKey.ToBytes()
Add ECDSASignature.ToBytes()
Add ECDSASignature.ToDERBytes()

