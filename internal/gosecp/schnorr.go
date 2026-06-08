package gosecp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	secp "github.com/allocz/secp256k1/internal/dcrsecp"
)

func schnorrKeyPairFromBytes(priv *PrivateKey, pub *PublicKey, privb []byte) {
	priv.k.SetByteSlice(privb)
	secp.ScalarBaseMultNonConst(&priv.k, &pub.p)
	pub.p.ToAffine()
	if pub.p.Y.IsOdd() {
		var privS secp.ModNScalar
		privS.Set(&priv.k)
		privS.Negate()
		secp.ScalarBaseMultNonConst(&privS, &pub.p)
		pub.p.ToAffine()
	}
}

func schnorrPublicKeyFromBytes(pub *PublicKey, pubb []byte) {
	pub.p.Z.SetInt(1)
	pub.p.X.SetByteSlice(pubb)
	secp.DecompressY(&pub.p.X, false, &pub.p.Y)
}

const scalarSize = 32

var (
	rfc6979ExtraDataV0 = [32]uint8{
		0xa3, 0xeb, 0x4c, 0x18, 0x2f, 0xae, 0x7e, 0xf4,
		0xe8, 0x10, 0xc6, 0xee, 0x13, 0xb0, 0xe9, 0x26,
		0x68, 0x6d, 0x71, 0xe8, 0x7f, 0x39, 0x4f, 0x79,
		0x9c, 0x00, 0xa5, 0x21, 0x03, 0xcb, 0x4e, 0x17,
	}
)

func schnorrSignExt(sig *SchnorrSignature, privKey *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) error {

	var privKeyScalar secp.ModNScalar
	privKeyScalar.Set(&privKey.k)

	if privKeyScalar.IsZero() {
		return fmt.Errorf("private key is zero")
	}

	var pub PublicKey
	PublicKeyFromPrivateKey(&pub, privKey)

	var pubKeyBytes [33]byte
	PublicKeyToCompressedBytes(pubKeyBytes[:], &pub)
	if pubKeyBytes[0] == secp.PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	if auxRand != nil {
		privBytes := privKeyScalar.Bytes()
		t := schnorrTaggedHash(
			schnorrTagBIP0340Aux, auxRand[:],
		)
		for i := range t {
			t[i] ^= privBytes[i]
		}

		rand := schnorrTaggedHash(
			schnorrTagBIP0340Nonce, t[:], pubKeyBytes[1:], msg,
		)

		var kPrime secp.ModNScalar
		kPrime.SetBytes((*[32]byte)(rand))

		if kPrime.IsZero() {
			return fmt.Errorf("generated nonce is zero")
		}

		err := schnorrSign(sig, &privKeyScalar, &kPrime, &pub,
			msg, fastSign)
		kPrime.Zero()
		if err != nil {
			return err
		}

		return nil
	}

	var privKeyBytes [scalarSize]byte
	privKeyScalar.PutBytes(&privKeyBytes)
	defer zeroArray32(&privKeyBytes)
	for iteration := uint32(0); ; iteration++ {
		var k secp.ModNScalar
		secp.NonceRFC6979(&k, privKeyBytes[:], msg,
			rfc6979ExtraDataV0[:], nil, iteration)

		err := schnorrSign(sig, &privKeyScalar, &k, &pub, msg, fastSign)
		k.Zero()
		if err != nil {
			continue
		}

		return nil
	}
}

func schnorrSign(sig *SchnorrSignature, privKey, nonce *secp.ModNScalar,
	pubKey *PublicKey, hash []byte, fastSign bool) error {

	var R secp.JacobianPoint
	k := *nonce
	secp.ScalarBaseMultNonConst(&k, &R)

	R.ToAffine()
	if R.Y.IsOdd() {
		k.Negate()
	}

	var pBytes [32]byte
	pubKey.p.X.PutBytes(&pBytes)
	commitment := schnorrTaggedHash(
		schnorrTagBIP0340Challenge, R.X.Bytes()[:], pBytes[:], hash,
	)

	var e secp.ModNScalar
	if overflow := e.SetBytes((*[32]byte)(commitment)); overflow != 0 {
		k.Zero()
		return fmt.Errorf("hash of (r || P || m) too big")
	}

	s := new(secp.ModNScalar).Mul2(&e, privKey).Add(&k)
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

func schnorrSignatureFromRS(sig *SchnorrSignature, r *secp.FieldVal,
	s *secp.ModNScalar) {

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

func newHash(newHash []byte) (*schnorrHash, error) {
	var sh schnorrHash
	err := sh.SetBytes(newHash)
	if err != nil {
		return nil, err
	}
	return &sh, err
}

func schnorrTaggedHash(tag []byte, msgs ...[]byte) *schnorrHash {
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

	taggedHash := h.Sum(nil)

	hash, _ := newHash(taggedHash)

	return hash
}

const (
	PubKeyBytesLen = 32
)

func schnorrParsePubKey(pub *secp.PublicKey, pubKeyStr []byte) error {
	if pubKeyStr == nil {
		err := fmt.Errorf("nil pubkey byte string")
		return err
	}
	if len(pubKeyStr) != PubKeyBytesLen {
		err := fmt.Errorf(
			"bad pubkey byte string size (want %v, have %v)",
			PubKeyBytesLen, len(pubKeyStr))
		return err
	}

	var keyCompressed [secp.PubKeyBytesLenCompressed]byte
	keyCompressed[0] = secp.PubKeyFormatCompressedEven
	copy(keyCompressed[1:], pubKeyStr)

	pub2, err := secp.ParsePubKey(keyCompressed[:])
	if err != nil {
		return err
	}
	*pub = *pub2
	return nil
}

func schnorrVerify(sig *SchnorrSignature, pub *PublicKey, msg []byte) bool {
	var pubb [65]byte
	PublicKeyToBytes(pubb[:], pub)

	return schnorrVerify3(sig, msg, pubb[1:33]) == nil
}

func schnorrVerify3(sig *SchnorrSignature, hash []byte,
	pubKeyBytes []byte) error {

	var pubKey secp.PublicKey
	err := schnorrParsePubKey(&pubKey, pubKeyBytes)
	if err != nil {
		return err
	}
	if !pubKey.IsOnCurve() {
		return fmt.Errorf("pubkey point is not on curve")
	}

	var rBytes [32]byte
	sig.r.PutBytesUnchecked(rBytes[:])
	var pubXBytes [32]byte
	pubKey.Xf.PutBytes(&pubXBytes)

	commitment := schnorrTaggedHash(schnorrTagBIP0340Challenge, rBytes[:],
		pubXBytes[:], hash)

	var e secp.ModNScalar
	e.SetBytes((*[32]byte)(commitment))

	e.Negate()

	var P, R, sG, eP secp.JacobianPoint
	pubKey.AsJacobian(&P)
	secp.ScalarBaseMultNonConst(&sig.s, &sG)
	secp.ScalarMultNonConst(&e, &P, &eP)
	secp.AddNonConst(&sG, &eP, &R)

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

func zeroArray32(a *[32]byte) {
	for i := range 32 {
		a[i] = 0x00
	}
}
