package gosecp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func schnorrKeyPairFromBytes(priv *PrivateKey, pub *PublicKey, privb []byte) {
	priv.k.SetByteSlice(privb)
	ScalarBaseMultNonConst(&priv.k, &pub.p)
	pub.p.ToAffine()
	if pub.p.Y.IsOdd() {
		var privS ModNScalar
		privS.Set(&priv.k)
		privS.Negate()
		ScalarBaseMultNonConst(&privS, &pub.p)
		pub.p.ToAffine()
	}
}

func isOnCurve(fx, fy *FieldVal) bool {
	// Elliptic curve equation for secp256k1 is: y^2 = x^3 + 7
	y2 := new(FieldVal).SquareVal(fy).Normalize()
	result := new(FieldVal).SquareVal(fx).Mul(fx).AddInt(7).Normalize()
	return y2.Equals(result)
}

func schnorrSignExt(sig *SchnorrSignature, privKey *PrivateKey, msg []byte,
	auxRandP *[32]byte, fastSign bool) error {

	var privKeyScalar ModNScalar
	privKeyScalar.Set(&privKey.k)
	defer privKeyScalar.Zero()

	if privKeyScalar.IsZero() {
		return fmt.Errorf("private key is zero")
	}

	var pub PublicKey
	pub.FromPrivateKey(privKey)

	var pubKeyBytes [33]byte
	pub.ToBytes33(pubKeyBytes[:])
	if pubKeyBytes[0] == PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	var auxRand [32]byte
	if auxRandP != nil {
		auxRand = *auxRandP
	}

	privBytes := privKeyScalar.Bytes()
	defer clear(privBytes[:])
	var t schnorrHash
	defer clear(t[:])
	schnorrTaggedHash(
		&t, schnorrTagBIP0340Aux, auxRand[:],
	)
	for i := range t {
		t[i] ^= privBytes[i]
	}

	var rand schnorrHash
	schnorrTaggedHash(
		&rand, schnorrTagBIP0340Nonce, t[:], pubKeyBytes[1:], msg,
	)

	var kPrime ModNScalar
	kPrime.SetBytes((*[32]byte)(&rand))

	if kPrime.IsZero() {
		return fmt.Errorf("generated nonce is zero")
	}

	err := schnorrSign(sig, &privKeyScalar, &kPrime, &pub, msg, fastSign)
	kPrime.Zero()
	if err != nil {
		return err
	}

	return nil
}

func schnorrSign(sig *SchnorrSignature, privKey, nonce *ModNScalar,
	pubKey *PublicKey, hash []byte, fastSign bool) error {

	var R JacobianPoint
	k := *nonce
	ScalarBaseMultNonConst(&k, &R)

	R.ToAffine()
	if R.Y.IsOdd() {
		k.Negate()
	}

	var pBytes [32]byte
	pubKey.p.X.PutBytes(&pBytes)
	var commitment schnorrHash
	schnorrTaggedHash(&commitment, schnorrTagBIP0340Challenge,
		R.X.Bytes()[:], pBytes[:], hash)

	var e ModNScalar
	if overflow := e.SetBytes((*[32]byte)(&commitment)); overflow != 0 {
		k.Zero()
		return fmt.Errorf("hash of (r || P || m) too big")
	}

	s := new(ModNScalar).Mul2(&e, privKey).Add(&k)
	k.Zero()

	schnorrSignatureFromRS(sig, &R.X, s)

	if !fastSign {
		err := schnorrVerify3(sig, hash, pBytes[:])
		if err != nil {
			return err
		}
	}

	return nil
}

func schnorrSignatureFromRS(sig *SchnorrSignature, r *FieldVal,
	s *ModNScalar) {

	sig.r.Set(r).Normalize()
	sig.s.Set(s)
}

var (
	schnorrTagBIP0340Challenge = []byte("BIP0340/challenge")
	schnorrTagBIP0340Aux       = []byte("BIP0340/aux")
	schnorrTagBIP0340Nonce     = []byte("BIP0340/nonce")
	schnorrTagTapSighash       = []byte("TapSighash")
	schnorrTagTapLeaf          = []byte("TapLeaf")
	schnorrTagTapBranch        = []byte("TapBranch")
	schnorrTagTapTweak         = []byte("TapTweak")

	precomputedTags = map[string]schnorrHash{
		string(schnorrTagBIP0340Challenge): sha256.Sum256(schnorrTagBIP0340Challenge),
		string(schnorrTagBIP0340Aux):       sha256.Sum256(schnorrTagBIP0340Aux),
		string(schnorrTagBIP0340Nonce):     sha256.Sum256(schnorrTagBIP0340Nonce),
		string(schnorrTagTapSighash):       sha256.Sum256(schnorrTagTapSighash),
		string(schnorrTagTapLeaf):          sha256.Sum256(schnorrTagTapLeaf),
		string(schnorrTagTapBranch):        sha256.Sum256(schnorrTagTapBranch),
		string(schnorrTagTapTweak):         sha256.Sum256(schnorrTagTapTweak),
	}
)

const hashSize = 32

type schnorrHash [hashSize]byte

func (hash schnorrHash) String() string {
	for i := range hashSize / 2 {
		hash[i], hash[hashSize-1-i] = hash[hashSize-1-i], hash[i]
	}
	return hex.EncodeToString(hash[:])
}

func (hash *schnorrHash) SetBytes(newHash []byte) error {
	nhlen := len(newHash)
	if nhlen != hashSize {
		return fmt.Errorf("invalid hash length of %v, want %v", nhlen,
			hashSize)
	}
	copy(hash[:], newHash)

	return nil
}

func schnorrHashInit(hash *schnorrHash, newHash []byte) error {
	err := hash.SetBytes(newHash)
	if err != nil {
		return err
	}
	return err
}

func schnorrTaggedHash(hash *schnorrHash, tag []byte, msgs ...[]byte) {
	shaTag, ok := precomputedTags[string(tag)]
	if !ok {
		shaTag = sha256.Sum256(tag)
	}

	h := sha256.New()
	h.Write(shaTag[:])
	h.Write(shaTag[:])

	for _, msg := range msgs {
		h.Write(msg)
	}

	var taggedHash [32]byte
	h.Sum(taggedHash[:0])

	_ = schnorrHashInit(hash, taggedHash[:])
}

const (
	pubKeyBytesLen = 32
)

func schnorrParsePubKey(pub *PublicKeyA, pubKeyStr []byte) error {
	if pubKeyStr == nil {
		err := fmt.Errorf("nil pubkey byte string")
		return err
	}
	if len(pubKeyStr) != pubKeyBytesLen {
		err := fmt.Errorf(
			"bad pubkey byte string size (want %v, have %v)",
			pubKeyBytesLen, len(pubKeyStr))
		return err
	}

	var keyCompressed [PubKeyBytesLenCompressed]byte
	keyCompressed[0] = PubKeyFormatCompressedEven
	copy(keyCompressed[1:], pubKeyStr)

	var pub2 PublicKeyA
	err := ParsePubKeyZeroAlloc(&pub2, keyCompressed[:])
	if err != nil {
		return err
	}
	*pub = pub2
	return nil
}

func schnorrVerify(sig *SchnorrSignature, pub *PublicKey, msg []byte) bool {
	var pubb [65]byte
	pubb[0] = 0x4
	pub.ToBytes64(pubb[1:])

	return schnorrVerify3(sig, msg, pubb[1:33]) == nil
}

func schnorrVerify3(sig *SchnorrSignature, hash []byte,
	pubKeyBytes []byte) error {

	var pubKey PublicKeyA
	err := schnorrParsePubKey(&pubKey, pubKeyBytes)
	if err != nil {
		return err
	}
	if !pubKey.IsOnCurve() {
		return fmt.Errorf("pubkey point is not on curve")
	}

	var pubX, pubY FieldVal
	pubKey.PutXY(&pubX, &pubY)
	var rBytes [32]byte
	sig.r.PutBytesUnchecked(rBytes[:])
	var pubXBytes [32]byte
	pubX.PutBytes(&pubXBytes)

	var commitment schnorrHash
	schnorrTaggedHash(&commitment, schnorrTagBIP0340Challenge, rBytes[:],
		pubXBytes[:], hash)

	var e ModNScalar
	e.SetBytes((*[32]byte)(&commitment))

	e.Negate()

	var P, R, sG, eP JacobianPoint
	pubKey.AsJacobian(&P)
	ScalarBaseMultNonConst(&sig.s, &sG)
	ScalarMultNonConst(&e, &P, &eP)
	AddNonConst(&sG, &eP, &R)

	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		return fmt.Errorf("calculated R point is the point at infinity")
	}

	R.ToAffine()
	if R.Y.IsOdd() {
		return fmt.Errorf("calculated R y-value is odd")
	}

	if !sig.r.Equals(&R.X) {
		return fmt.Errorf("calculated R point was not given R")
	}

	return nil
}
