package secp256k1

import "github.com/allocz/secp256k1/internal/gosecp"

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
