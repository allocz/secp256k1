//go:build cgo && (!amd64 || forceportable)

package secp

func PublicKeyToBytes(data []byte, pub *PublicKey) {
	publicKeyToBytes(data, pub)
}

func ECDSASignatureFromBytes(sig *ECDSASignature, data []byte) error {
	return ecdsaSignatureFromBytes(sig, data)
}

func ECDSASignatureToBytes(data []byte, sig *ECDSASignature) {
	ecdsaSignatureToBytes(data, sig)
}
