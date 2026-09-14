//go:build !amd64 || forceportable

package gosecp

func ecdsaSign(sig *ECDSASignature, priv *PrivateKey, hash []byte) {
	priv2 := PrivateKeyA{Key: priv.k}
	defer func() {
		priv2 = PrivateKeyA{}
	}()

	var sig2 ECDSASignatureA
	SignZeroAlloc(&sig2, &priv2, hash)
	sig2.PutRS(&sig.r, &sig.s)
}

func ecdsaVerify(sig *ECDSASignature, pub *PublicKey, hash []byte) bool {
	var sig2 ECDSASignatureA
	sig2.SetRS(&sig.r, &sig.s)

	var pub2 PublicKeyA
	pub2.SetXY(&pub.p.X, &pub.p.Y)

	return sig2.Verify(hash, &pub2)
}
