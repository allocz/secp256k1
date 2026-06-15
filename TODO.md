Add vector tests for ECDSA

Speed up C implementation: firstly, use unsafe for
serialization/deserialization, then if needed, drop down to assembly:
* PublicKeyFromBytes
* PrivateKeyFromBytes
* ECDSASignatureToBytes
* ECDSASignatureFromBytes
* PublicKeyToBytes

Add ECDSASignatureFromDERBytes(sigOut, data, lax bool)

Add PrivateKey.ToBytes()
Add PublicKey.ToBytes()
Add ECDSASignature.ToBytes()
Add ECDSASignature.ToDERBytes()

Would be nice to PublicKeyFromBytes work with
* 32 byte X only pubkey with even Y
* 64 byte XY pubkey
* 33 byte compressed pubkey


