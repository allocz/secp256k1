//go:build cgo && amd64 && !forceportable

package secp

func PublicKeyToBytes(data []byte, pub *PublicKey) {
	publicKeyToBytesAmd64(data, pub)
}

func ECDSASignatureFromBytes(sig *ECDSASignature, data []byte) error {
	return ecdsaSignatureFromBytesAmd64(sig, data)
}

func ECDSASignatureToBytes(data []byte, sig *ECDSASignature) {
	ecdsaSignatureToBytesAmd64(data, sig)
}
