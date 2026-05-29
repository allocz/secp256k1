package gosecp

import (
	secp "github.com/allocz/secp256k1/internal/dcrsecp"
	ecdsa "github.com/allocz/secp256k1/internal/dcrsecp/ecdsa"
)

func ecdsaSign(sig *ECDSASignature, priv *PrivateKey, hash []byte) {
	priv2 := secp.PrivateKey{Key: priv.k}

	sig2 := ecdsa.Sign(&priv2, hash)
	sig.r = sig2.Rs
	sig.s = sig2.Ss
}

func ecdsaVerify(sig *ECDSASignature, pub *PublicKey, hash []byte) bool {
	sig2 := ecdsa.Signature{Rs: sig.r, Ss: sig.s}

	pub2 := secp.PublicKey{Xf: pub.p.X, Yf: pub.p.Y}

	return sig2.Verify(hash, &pub2)
}
