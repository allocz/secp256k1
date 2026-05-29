package gosecp

import secp "github.com/allocz/secp256k1/internal/dcrsecp"

type PrivateKey struct {
	k secp.ModNScalar
}

func PrivateKeyFromBytes(priv *PrivateKey, data []byte) {
	priv.k.SetByteSlice(data)
}

func PrivateKeyToBytes(data []byte, priv *PrivateKey) {
	priv.k.PutBytesUnchecked(data)
}
