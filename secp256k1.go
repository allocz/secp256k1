package secp256k1

import (
	"github.com/allocz/secp256k1/internal/gosecp"
)

type PrivateKey = gosecp.PrivateKey

func PrivateKeyFromBytes(priv *PrivateKey, data []byte) {
	gosecp.PrivateKeyFromBytes(priv, data)
}

func PrivateKeyToBytes(data []byte, priv *PrivateKey) {
	gosecp.PrivateKeyToBytes(data, priv)
}

type PublicKey = gosecp.PublicKey

func PublicKeyFromBytes(pub *PublicKey, data []byte) {
	gosecp.PublicKeyFromBytes(pub, data)
}

func PublicKeyToBytes(data []byte, pub *PublicKey) {
	gosecp.PublicKeyToBytes(data, pub)
}

func PublicKeyFromPrivateKey(pub *PublicKey, priv *PrivateKey) {
	gosecp.PublicKeyFromPrivateKey(pub, priv)
}

type ECDSASignature = gosecp.ECDSASignature

func ECDSASignatureFromBytes(sig *ECDSASignature, data []byte) {
	gosecp.ECDSASignatureFromBytes(sig, data)
}

func ECDSASignatureToBytes(data []byte, sig *ECDSASignature) {
	gosecp.ECDSASignatureToBytes(data, sig)
}

func ECDSASign(sig *ECDSASignature, priv *PrivateKey, hash []byte) {
	gosecp.ECDSASign(sig, priv, hash)
}

func ECDSAVerify(sig *ECDSASignature, pub *PublicKey, hash []byte) bool {
	return gosecp.ECDSAVerify(sig, pub, hash)
}

type SchnorrSignature = gosecp.SchnorrSignature

func SchnorrKeyPairFromBytes(priv *PrivateKey, pub *PublicKey,
	data []byte) error {

	gosecp.SchnorrKeyPairFromBytes(priv, pub, data)
	return nil
}

func SchnorrPublicKeyFromBytes(pub *PublicKey, data []byte) error {
	gosecp.SchnorrPublicKeyFromBytes(pub, data)
	return nil
}

func SchnorrSignatureFromBytes(sig *SchnorrSignature,
	data []byte) error {

	return gosecp.SchnorrSignatureFromBytes(sig, data)
}

func SchnorrSign(sig *SchnorrSignature, priv *PrivateKey, msg []byte) error {
	return SchnorrSignExt(sig, priv, msg, nil, false)
}

func SchnorrSignExt(sig *SchnorrSignature, priv *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) error {

	return gosecp.SchnorrSignExt(sig, priv, msg, auxRand, fastSign)
}
