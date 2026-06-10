//go:build cgo && amd64

package secp256k1

import (
	//"github.com/allocz/secp256k1/internal/gosecp"
	"github.com/allocz/secp256k1/internal/secp"
)

type PrivateKey = secp.PrivateKey

func PrivateKeyFromBytes(priv *PrivateKey, data []byte) error {
	return secp.PrivateKeyFromBytes(priv, data)
}

func PrivateKeyToBytes(data []byte, priv *PrivateKey) {
	secp.PrivateKeyToBytes(data, priv)
}

type PublicKey = secp.PublicKey

func PublicKeyFromBytes(pub *PublicKey, data []byte) error {
	return secp.PublicKeyFromBytes(pub, data)
}

func PublicKeyToBytes(data []byte, pub *PublicKey) {
	secp.PublicKeyToBytes(data, pub)
}

func PublicKeyFromPrivateKey(pub *PublicKey, priv *PrivateKey) {
	secp.PublicKeyFromPrivateKey(pub, priv)
}

type ECDSASignature = secp.ECDSASignature

func ECDSASignatureFromBytes(sig *ECDSASignature, data []byte) error {
	return secp.ECDSASignatureFromBytes(sig, data)
}

func ECDSASignatureToBytes(data []byte, sig *ECDSASignature) {
	secp.ECDSASignatureToBytes(data, sig)
}

func ECDSASign(sig *ECDSASignature, priv *PrivateKey, hash []byte) error {
	return secp.ECDSASign(sig, priv, hash)
}

func ECDSAVerify(sig *ECDSASignature, pub *PublicKey, hash []byte) bool {
	return secp.ECDSAVerify(sig, pub, hash)
}

type SchnorrSignature = secp.SchnorrSignature

func SchnorrKeyPairFromBytes(priv *PrivateKey, pub *PublicKey,
	data []byte) error {

	return secp.SchnorrKeyPairFromBytes(priv, pub, data)
}

func SchnorrPublicKeyFromBytes(pub *PublicKey, data []byte) error {
	return secp.SchnorrPublicKeyFromBytes(pub, data)
}

func SchnorrSignatureFromBytes(sig *SchnorrSignature, data []byte) error {
	return secp.SchnorrSignatureFromBytes(sig, data)
}

func SchnorrSign(sig *SchnorrSignature, priv *PrivateKey, msg []byte) error {
	return SchnorrSignExt(sig, priv, msg, nil, false)
}

func SchnorrSignExt(sig *SchnorrSignature, priv *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) error {

	return secp.SchnorrSignExt(sig, priv, msg, auxRand, fastSign)
}
