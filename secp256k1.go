//go:build !cgo

package secp256k1

import (
	"github.com/allocz/secp256k1/internal/gosecp"
)

type PrivateKey = gosecp.PrivateKey

func PrivateKeyFromBytes(priv *PrivateKey, data []byte) error {
	gosecp.PrivateKeyFromBytes(priv, data)
	return nil
}

func PrivateKeyToBytes(data []byte, priv *PrivateKey) {
	gosecp.PrivateKeyToBytes(data, priv)
}

type PublicKey = gosecp.PublicKey

func PublicKeyFromBytes(pub *PublicKey, data []byte) error {
	gosecp.PublicKeyFromBytes(pub, data)
	return nil
}

func PublicKeyToBytes(data []byte, pub *PublicKey) {
	gosecp.PublicKeyToBytes(data, pub)
}

func PublicKeyFromPrivateKey(pub *PublicKey, priv *PrivateKey) {
	gosecp.PublicKeyFromPrivateKey(pub, priv)
}

type ECDSASignature = gosecp.ECDSASignature

func ECDSASignatureFromBytes(sig *ECDSASignature, data []byte) error {
	gosecp.ECDSASignatureFromBytes(sig, data)
	return nil
}

func ECDSASignatureToBytes(data []byte, sig *ECDSASignature) {
	gosecp.ECDSASignatureToBytes(data, sig)
}

func ECDSASign(sig *ECDSASignature, priv *PrivateKey, hash []byte) error {
	gosecp.ECDSASign(sig, priv, hash)
	return nil
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
	return gosecp.SchnorrPublicKeyFromBytes(pub, data)
}

func SchnorrSignatureFromBytes(sig *SchnorrSignature, data []byte) error {
	return gosecp.SchnorrSignatureFromBytes(sig, data)
}

func SchnorrSign(sig *SchnorrSignature, priv *PrivateKey, msg []byte) error {
	return SchnorrSignExt(sig, priv, msg, nil, false)
}

func SchnorrSignExt(sig *SchnorrSignature, priv *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) error {

	return gosecp.SchnorrSignExt(sig, priv, msg, auxRand, fastSign)
}
