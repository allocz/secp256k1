Improve schnorr tests by setting error kinds

C implementation: zero out allocations of:
* PublicKeyToBytes
* SchnorrKeyPairFromBytes
* SchnorrPublicKeyFromBytes
* SchnorrSign
* SchnorrVerify

