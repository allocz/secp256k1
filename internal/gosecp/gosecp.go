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

type PublicKey struct {
	p secp.JacobianPoint
}

func PublicKeyFromBytes(pub *PublicKey, data []byte) {
	pub.p.X.SetByteSlice(data[1:33])
	pub.p.Y.SetByteSlice(data[33:65])
	pub.p.Z.SetInt(1)
}

func PublicKeyToBytes(data []byte, pub *PublicKey) {
	data[0] = 0x04 // Uncompressed
	pub.p.X.PutBytesUnchecked(data[1:])
	pub.p.Y.PutBytesUnchecked(data[33:])
}

func PublicKeyFromPrivateKey(pub *PublicKey, priv *PrivateKey) {
	secp.ScalarBaseMultNonConst(&priv.k, &pub.p)
	pub.p.ToAffine()
}

type ECDSASignature struct {
	r, s secp.ModNScalar
}

func ECDSASignatureFromBytes(sig *ECDSASignature, data []byte) {
	sig.r.SetByteSlice(data[:32])
	sig.s.SetByteSlice(data[32:])
}

func ECDSASignatureToBytes(data []byte, sig *ECDSASignature) {
	sig.r.PutBytesUnchecked(data)
	sig.s.PutBytesUnchecked(data[32:])
}
