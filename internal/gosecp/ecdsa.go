package gosecp

import (
	secp "github.com/allocz/secp256k1/internal/dcrsecp"
	ecdsa "github.com/allocz/secp256k1/internal/dcrsecp/ecdsa"
)

func ecdsaSign(sig *ECDSASignature, priv *PrivateKey, hash []byte) {
	priv2 := secp.PrivateKey{Key: priv.k}
	defer func() {
		priv2 = secp.PrivateKey{}
	}()

	var sig2 ecdsa.Signature
	ecdsa.SignZeroAlloc(&sig2, &priv2, hash)
	sig2.PutRS(&sig.r, &sig.s)
}

func ecdsaVerify(sig *ECDSASignature, pub *PublicKey, hash []byte) bool {
	var sig2 ecdsa.Signature
	sig2.SetRS(&sig.r, &sig.s)

	var pub2 secp.PublicKey
	pub2.SetXY(&pub.p.X, &pub.p.Y)

	return sig2.Verify(hash, &pub2)
}
