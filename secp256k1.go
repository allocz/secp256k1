package secp256k1

import "github.com/allocz/secp256k1/internal/gosecp"

type PrivateKey = gosecp.PrivateKey

func PrivateKeyFromBytes(priv *PrivateKey, data []byte) {
	gosecp.PrivateKeyFromBytes(priv, data)
}

func PrivateKeyToBytes(data []byte, priv *PrivateKey) {
	gosecp.PrivateKeyToBytes(data, priv)
}
