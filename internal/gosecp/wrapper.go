//go:build !amd64 || forceportable

package gosecp

import (
	secp "github.com/allocz/secp256k1/internal/dcrsecp"
	ecdsa "github.com/allocz/secp256k1/internal/dcrsecp/ecdsa"
)

const PubKeyFormatCompressedOdd = secp.PubKeyFormatCompressedOdd
const PubKeyFormatCompressedEven = secp.PubKeyFormatCompressedEven

const PubKeyBytesLenCompressed = secp.PubKeyBytesLenCompressed

type ModNScalar = secp.ModNScalar
type JacobianPoint = secp.JacobianPoint
type FieldVal = secp.FieldVal
type PrivateKeyA = secp.PrivateKey
type PublicKeyA = secp.PublicKey
type ECDSASignatureA = ecdsa.Signature

func DecompressY(x *FieldVal, odd bool, resultY *FieldVal) bool {
	return secp.DecompressY(x, odd, resultY)
}

func ScalarBaseMultNonConst(k *ModNScalar, result *JacobianPoint) {
	secp.ScalarBaseMultNonConst(k, result)
}

func SignZeroAlloc(sigOut *ecdsa.Signature, key *secp.PrivateKey,
	hash []byte) {

	ecdsa.SignZeroAlloc(sigOut, key, hash)
}

func ParsePubKeyZeroAlloc(pubOut *PublicKeyA, serialized []byte) error {
	return secp.ParsePubKeyZeroAlloc(pubOut, serialized)
}

func ScalarMultNonConst(k *ModNScalar, point, result *JacobianPoint) {
	secp.ScalarMultNonConst(k, point, result)
}

func AddNonConst(p1, p2, result *JacobianPoint) {
	secp.AddNonConst(p1, p2, result)
}
