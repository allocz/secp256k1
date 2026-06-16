//go:build !cgo

package secp256k1

import (
	"github.com/allocz/secp256k1/internal/gosecp"
)

type PrivateKey = gosecp.PrivateKey

type PublicKey = gosecp.PublicKey

type ECDSASignature = gosecp.ECDSASignature

func SchnorrKeyPairFromBytes(priv *PrivateKey, pub *PublicKey,
	data []byte) error {

	gosecp.SchnorrKeyPairFromBytes32(priv, pub, data)
	return nil
}

type SchnorrSignature = gosecp.SchnorrSignature
