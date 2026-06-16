//go:build cgo && amd64

package secp256k1

import (
	"github.com/allocz/secp256k1/internal/secp"
)

type PrivateKey = secp.PrivateKey

type PublicKey = secp.PublicKey

type ECDSASignature = secp.ECDSASignature

func SchnorrKeyPairFromBytes32(priv *PrivateKey, pub *PublicKey,
	data []byte) error {

	secp.SchnorrKeyPairFromBytes32(priv, pub, data)
	return nil
}

type SchnorrSignature = secp.SchnorrSignature
