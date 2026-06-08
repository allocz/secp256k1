// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2023 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ecdsa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/allocz/secp256k1/internal/dcrsecp"
)

// hexToBytes converts the passed hex string into bytes and will panic if there
// is an error.  This is only provided for the hard-coded constants so errors in
// the source code can be detected. It will only (and must only) be called with
// hard-coded values.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

// TestSignatureParsing ensures that signatures are properly parsed according
// to DER rules.  The error paths are tested as well.
func TestSignatureParsing(t *testing.T) {
	tests := []struct {
		name string
		sig  []byte
		err  error
	}{{
		// signature from Decred blockchain tx
		// 76634e947f49dfc6228c3e8a09cd3e9e15893439fc06df7df0fc6f08d659856c:0
		name: "valid signature 1",
		sig: hexToBytes("3045022100cd496f2ab4fe124f977ffe3caa09f7576d8a34156" +
			"b4e55d326b4dffc0399a094022013500a0510b5094bff220c74656879b8ca03" +
			"69d3da78004004c970790862fc03"),
		err: nil,
	}, {
		// signature from Decred blockchain tx
		// 76634e947f49dfc6228c3e8a09cd3e9e15893439fc06df7df0fc6f08d659856c:1
		name: "valid signature 2",
		sig: hexToBytes("3044022036334e598e51879d10bf9ce3171666bc2d1bbba6164" +
			"cf46dd1d882896ba35d5d022056c39af9ea265c1b6d7eab5bc977f06f81e35c" +
			"dcac16f3ec0fd218e30f2bad2a"),
		err: nil,
	}, {
		name: "empty",
		sig:  nil,
		err:  ErrSigTooShort,
	}, {
		name: "too short",
		sig:  hexToBytes("30050201000200"),
		err:  ErrSigTooShort,
	}, {
		name: "too long",
		sig: hexToBytes("3045022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef074022030e09575e7a1541aa018876a4003cefe1b061a" +
			"90556b5140c63e0ef8481352480101"),
		err: ErrSigTooLong,
	}, {
		name: "bad ASN.1 sequence id",
		sig: hexToBytes("3145022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef074022030e09575e7a1541aa018876a4003cefe1b061a" +
			"90556b5140c63e0ef848135248"),
		err: ErrSigInvalidSeqID,
	}, {
		name: "mismatched data length (short one byte)",
		sig: hexToBytes("3044022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef074022030e09575e7a1541aa018876a4003cefe1b061a" +
			"90556b5140c63e0ef848135248"),
		err: ErrSigInvalidDataLen,
	}, {
		name: "mismatched data length (long one byte)",
		sig: hexToBytes("3046022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef074022030e09575e7a1541aa018876a4003cefe1b061a" +
			"90556b5140c63e0ef848135248"),
		err: ErrSigInvalidDataLen,
	}, {
		name: "bad R ASN.1 int marker",
		sig: hexToBytes("304403204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d6" +
			"24c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56c" +
			"bbac4622082221a8768d1d09"),
		err: ErrSigInvalidRIntID,
	}, {
		name: "zero R length",
		sig: hexToBytes("30240200022030e09575e7a1541aa018876a4003cefe1b061a90" +
			"556b5140c63e0ef848135248"),
		err: ErrSigZeroRLen,
	}, {
		name: "negative R (too little padding)",
		sig: hexToBytes("30440220b2ec8d34d473c3aa2ab5eb7cc4a0783977e5db8c8daf" +
			"777e0b6d7bfa6b6623f302207df6f09af2c40460da2c2c5778f636d3b2e27e20" +
			"d10d90f5a5afb45231454700"),
		err: ErrSigNegativeR,
	}, {
		name: "too much R padding",
		sig: hexToBytes("304402200077f6e93de5ed43cf1dfddaa79fca4b766e1a8fc879" +
			"b0333d377f62538d7eb5022054fed940d227ed06d6ef08f320976503848ed1f5" +
			"2d0dd6d17f80c9c160b01d86"),
		err: ErrSigTooMuchRPadding,
	}, {
		name: "bad S ASN.1 int marker",
		sig: hexToBytes("3045022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef074032030e09575e7a1541aa018876a4003cefe1b061a" +
			"90556b5140c63e0ef848135248"),
		err: ErrSigInvalidSIntID,
	}, {
		name: "missing S ASN.1 int marker",
		sig: hexToBytes("3023022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef074"),
		err: ErrSigMissingSTypeID,
	}, {
		name: "S length missing",
		sig: hexToBytes("3024022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef07402"),
		err: ErrSigMissingSLen,
	}, {
		name: "invalid S length (short one byte)",
		sig: hexToBytes("3045022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef074021f30e09575e7a1541aa018876a4003cefe1b061a" +
			"90556b5140c63e0ef848135248"),
		err: ErrSigInvalidSLen,
	}, {
		name: "invalid S length (long one byte)",
		sig: hexToBytes("3045022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef074022130e09575e7a1541aa018876a4003cefe1b061a" +
			"90556b5140c63e0ef848135248"),
		err: ErrSigInvalidSLen,
	}, {
		name: "zero S length",
		sig: hexToBytes("3025022100f5353150d31a63f4a0d06d1f5a01ac65f7267a719e" +
			"49f2a1ac584fd546bef0740200"),
		err: ErrSigZeroSLen,
	}, {
		name: "negative S (too little padding)",
		sig: hexToBytes("304402204fc10344934662ca0a93a84d14d650d8a21cf2ab91f6" +
			"08e8783d2999c955443202208441aacd6b17038ff3f6700b042934f9a6fea0ce" +
			"c2051b51dc709e52a5bb7d61"),
		err: ErrSigNegativeS,
	}, {
		name: "too much S padding",
		sig: hexToBytes("304402206ad2fdaf8caba0f2cb2484e61b81ced77474b4c2aa06" +
			"9c852df1351b3314fe20022000695ad175b09a4a41cd9433f6b2e8e83253d6a7" +
			"402096ba313a7be1f086dde5"),
		err: ErrSigTooMuchSPadding,
	}, {
		name: "R == 0",
		sig: hexToBytes("30250201000220181522ec8eca07de4860a4acdd12909d831cc5" +
			"6cbbac4622082221a8768d1d09"),
		err: ErrSigRIsZero,
	}, {
		name: "R == N",
		sig: hexToBytes("3045022100fffffffffffffffffffffffffffffffebaaedce6af" +
			"48a03bbfd25e8cd03641410220181522ec8eca07de4860a4acdd12909d831cc5" +
			"6cbbac4622082221a8768d1d09"),
		err: ErrSigRTooBig,
	}, {
		name: "R > N (>32 bytes)",
		sig: hexToBytes("3045022101cd496f2ab4fe124f977ffe3caa09f756283910fc1a" +
			"96f60ee6873e88d3cfe1d50220181522ec8eca07de4860a4acdd12909d831cc5" +
			"6cbbac4622082221a8768d1d09"),
		err: ErrSigRTooBig,
	}, {
		name: "R > N",
		sig: hexToBytes("3045022100fffffffffffffffffffffffffffffffebaaedce6af" +
			"48a03bbfd25e8cd03641420220181522ec8eca07de4860a4acdd12909d831cc5" +
			"6cbbac4622082221a8768d1d09"),
		err: ErrSigRTooBig,
	}, {
		name: "S == 0",
		sig: hexToBytes("302502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d6" +
			"24c6c61548ab5fb8cd41020100"),
		err: ErrSigSIsZero,
	}, {
		name: "S == N",
		sig: hexToBytes("304502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d6" +
			"24c6c61548ab5fb8cd41022100fffffffffffffffffffffffffffffffebaaedc" +
			"e6af48a03bbfd25e8cd0364141"),
		err: ErrSigSTooBig,
	}, {
		name: "S > N (>32 bytes)",
		sig: hexToBytes("304502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d6" +
			"24c6c61548ab5fb8cd4102210113500a0510b5094bff220c74656879b784b246" +
			"ba89c0a07bc49bcf05d8993d44"),
		err: ErrSigSTooBig,
	}, {
		name: "S > N",
		sig: hexToBytes("304502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d6" +
			"24c6c61548ab5fb8cd41022100fffffffffffffffffffffffffffffffebaaedc" +
			"e6af48a03bbfd25e8cd0364142"),
		err: ErrSigSTooBig,
	}}

	for _, test := range tests {
		_, err := ParseDERSignature(test.sig)
		if !errors.Is(err, test.err) {
			t.Errorf("%s mismatched err -- got %v, want %v", test.name, err,
				test.err)
			continue
		}
	}
}

// TestSignatureSerialize ensures that serializing signatures works as expected.
func TestSignatureSerialize(t *testing.T) {
	tests := []struct {
		name     string
		ecsig    *Signature
		expected []byte
	}{{
		// signature from bitcoin blockchain tx
		// 0437cd7f8525ceed2324359c2d0ba26006d92d85
		"valid 1 - r and s most significant bits are zero",
		&Signature{
			Rs: *hexToModNScalar("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41"),
			Ss: *hexToModNScalar("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"),
		},
		hexToBytes("304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d62" +
			"4c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc" +
			"56cbbac4622082221a8768d1d09"),
	}, {
		// signature from bitcoin blockchain tx
		// cb00f8a0573b18faa8c4f467b049f5d202bf1101d9ef2633bc611be70376a4b4
		"valid 2 - r most significant bit is one",
		&Signature{
			Rs: *hexToModNScalar("82235e21a2300022738dabb8e1bbd9d19cfb1e7ab8c30a23b0afbb8d178abcf3"),
			Ss: *hexToModNScalar("24bf68e256c534ddfaf966bf908deb944305596f7bdcc38d69acad7f9c868724"),
		},
		hexToBytes("304502210082235e21a2300022738dabb8e1bbd9d19cfb1e7ab8c" +
			"30a23b0afbb8d178abcf3022024bf68e256c534ddfaf966bf908deb94430" +
			"5596f7bdcc38d69acad7f9c868724"),
	}, {
		// signature from bitcoin blockchain tx
		// fda204502a3345e08afd6af27377c052e77f1fefeaeb31bdd45f1e1237ca5470
		//
		// Note that signatures with an S component that is > half the group
		// order are neither allowed nor produced in Decred, so this has been
		// modified to expect the equally valid low S signature variant.
		"valid 3 - s most significant bit is one",
		&Signature{
			Rs: *hexToModNScalar("1cadddc2838598fee7dc35a12b340c6bde8b389f7bfd19a1252a17c4b5ed2d71"),
			Ss: *hexToModNScalar("c1a251bbecb14b058a8bd77f65de87e51c47e95904f4c0e9d52eddc21c1415ac"),
		},
		hexToBytes("304402201cadddc2838598fee7dc35a12b340c6bde8b389f7bfd1" +
			"9a1252a17c4b5ed2d7102203e5dae44134eb4fa757428809a2178199e66f" +
			"38daa53df51eaa380cab4222b95"),
	}, {
		"zero signature",
		&Signature{
			Rs: *new(secp256k1.ModNScalar).SetInt(0),
			Ss: *new(secp256k1.ModNScalar).SetInt(0),
		},
		hexToBytes("3006020100020100"),
	}}

	for i, test := range tests {
		result := test.ecsig.Serialize()
		if !bytes.Equal(result, test.expected) {
			t.Errorf("Serialize #%d (%s) unexpected result:\n"+
				"got:  %x\nwant: %x", i, test.name, result,
				test.expected)
		}
	}
}

// signTest describes tests for producing and verifying ECDSA signatures for a
// selected set of private keys, messages, and nonces that have been verified
// independently with the Sage computer algebra system.  It is defined
// separately since it is intended for use in both normal and compact signature
// tests.
type signTest struct {
	name     string // test description
	key      string // hex encoded private key
	msg      string // hex encoded message to sign before hashing
	hash     string // hex encoded hash of the message to sign
	nonce    string // hex encoded nonce to use in the signature calculation
	rfc6979  bool   // whether or not the nonce is an RFC6979 nonce
	wantSigR string // hex encoded expected signature R
	wantSigS string // hex encoded expected signature S
	wantCode byte   // expected public key recovery code
}

// signTests returns several tests for ECDSA signatures that use a selected set
// of private keys, messages, and nonces that have been verified independently
// with the Sage computer algebra system.  It is defined here versus inside a
// specific test function scope so it can be shared for both normal and compact
// signature tests.
func signTests(t *testing.T) []signTest {
	t.Helper()

	tests := []signTest{{
		name:     "key 0x1, sha256(0x01020304), rfc6979 nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000001",
		msg:      "01020304",
		hash:     "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
		nonce:    "de51033ff911a6e7f5dc196bec485ab9c923b5b2167c19d744dbc91fb1784668",
		rfc6979:  true,
		wantSigR: "cb28623215297cda8872a5ad53dae1248ec3a7c049221c50b83f3cb3345f5f9b",
		wantSigS: "0a27f166d1db71cc6b4fbd5303d79b5d1706ecec5474529dfa19195800492599",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x1, sha256(0x01020304), random nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000001",
		msg:      "01020304",
		hash:     "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
		nonce:    "a6df66500afeb7711d4c8e2220960855d940a5ed57260d2c98fbf6066cca283e",
		rfc6979:  false,
		wantSigR: "b073759a96a835b09b79e7b93c37fdbe48fb82b000c4a0e1404ba5d1fbc15d0a",
		wantSigS: "1c2456f15bbbc27b8854e2aad5dee6ec1ee3b4f200f124c2a66fbaeb4f2103e8",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x2, sha256(0x01020304), rfc6979 nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000002",
		msg:      "01020304",
		hash:     "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
		nonce:    "c920fd1b7aac9d22465f8fa4d26ed998412496fe20f1f424dd957119c243b5bf",
		rfc6979:  true,
		wantSigR: "8e989e7de833caeb017354b215fca6d198357dce86623debf66ff85da70671b9",
		wantSigS: "403d28ef2f82f58fc27afa2bfe828b8f4819d462a8f7f257c2c1a99ca42efd4b",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x2, sha256(0x01020304), random nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000002",
		msg:      "01020304",
		hash:     "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
		nonce:    "679a6d36e7fe6c02d7668af86d78186e8f9ccc04371ac1c8c37939d1f5cae07a",
		rfc6979:  false,
		wantSigR: "4a090d82f48ca12d9e7aa24b5dcc187ee0db2920496f671d63e86036aaa7997e",
		wantSigS: "3cf2b5379aefa444259f33acc09c6359a7c19e1d37f65c55615b117eb2b37154",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x1, sha256(0x0102030405), rfc6979 nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000001",
		msg:      "0102030405",
		hash:     "74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0",
		nonce:    "cc6c36ac908777e5e8cb1a15d8a50377577edeeee0ae8138b4352b400cb7f7e0",
		rfc6979:  true,
		wantSigR: "a947fedb725f2873f711f2c679cfbd2c5d1da9fb3d3e1d6d92bcdb99ed907ec0",
		wantSigS: "7bb7c665a32f5e072671e615a7d1d3535eb2965951622224ab138cd2d62837a3",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x1, sha256(0x0102030405), random nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000001",
		msg:      "0102030405",
		hash:     "74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0",
		nonce:    "65f880c892fdb6e7f74f76b18c7c942cfd037ef9cf97c39c36e08bbc36b41616",
		rfc6979:  false,
		wantSigR: "72e5666f4e9d1099447b825cf737ee32112f17a67e2ca7017ae098da31dfbb8b",
		wantSigS: "33fee9f6ac0e18373d9b925116243e9dbcb8d414728a17bac590c77f9025455e",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x2, sha256(0x0102030405), rfc6979 nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000002",
		msg:      "0102030405",
		hash:     "74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0",
		nonce:    "eea19542f880f9719136c1fdcaff9c021464816b2257d857ce6e0f268b67821d",
		rfc6979:  true,
		wantSigR: "456ac7a631501ae87e749f9d60786806677a87c32531fcbf58757957799f1d8a",
		wantSigS: "32c624d4a2b2c31e3a622a79bf0b76f9a8a52d896a82708bad7447bb9a178168",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "key 0x2, sha256(0x0102030405), random nonce",
		key:      "0000000000000000000000000000000000000000000000000000000000000002",
		msg:      "0102030405",
		hash:     "74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0",
		nonce:    "026ece4cfb704733dd5eef7898e44c33bd5a0d749eb043f48705e40fa9e9afa0",
		rfc6979:  false,
		wantSigR: "3c4c5a2f217ea758113fd4e89eb756314dfad101a300f48e5bd764d3b6e0f8bf",
		wantSigS: "1f6c2398b15ea7e8be3baad2b9eef51a5ce154d2e0bb2dde3f8ceda0ad9160d7",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 1, sha256(0x01), rfc6979 nonce",
		key:      "a1becef2069444a9dc6331c3247e113c3ee142edda683db8643f9cb0af7cbe33",
		msg:      "01",
		hash:     "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
		nonce:    "4f278b0247d2cba34b114085c3eb6ce0352312ffb81ade0cc8bfef0e395f0345",
		rfc6979:  true,
		wantSigR: "b885a6d84887854be35798f310a817f87215678a8309f198ffffe2ba11683447",
		wantSigS: "1c46239e91f1be44f1b9678b245921b79abd5048a88390cda4763861c2d2f71b",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 2, sha256(0x02), rfc6979 nonce",
		key:      "59930b76d4b15767ec0e8c8e5812aa2e57db30c6af7963e2a6295ba02af5416b",
		msg:      "02",
		hash:     "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986",
		nonce:    "16e17a66e66f068e419e55624adcfc0ebd1b982a24735eec4a5160b97ee9cb40",
		rfc6979:  true,
		wantSigR: "ff943d543372babd062dbee31d75678b90c2af8be2234eb942b544b78773cde9",
		wantSigS: "296df6cef1906ddec34638bc43ad36d0f59ef6045729cde6b1ba379a94ff9c4d",
		wantCode: 0,
	}, {
		name:     "random key 3, sha256(0x03), rfc6979 nonce",
		key:      "c5b205c36bb7497d242e96ec19a2a4f086d8daa919135cf490d2b7c0230f0e91",
		msg:      "03",
		hash:     "084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5",
		nonce:    "0ad861c4c68058ab427e1e93f901e3a0243faab7116e0f1b9fdfb08c9944d1a3",
		rfc6979:  true,
		wantSigR: "ee30685ad28292a6efde51c6c522af06b5b3cb1f3639a44999790745a453501b",
		wantSigS: "688df91f64698a32ac02325b33c7199809659359814ed33b51a031552d37c106",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 4, sha256(0x04), rfc6979 nonce",
		key:      "65b46d4eb001c649a86309286aaf94b18386effe62c2e1586d9b1898ccf0099b",
		msg:      "04",
		hash:     "e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71",
		nonce:    "ec72e3784388d9db6121055d8a29b6ac3dfcb072702ffd06676646d206a8ee34",
		rfc6979:  true,
		wantSigR: "b409239bf64355739f86f832aeb4653d17fe8a2c8345554c9510c26226d279d7",
		wantSigS: "58288654fd273c9727d46d5b24ab050e91a7dd7acbb0c3d5b294b4dc7b592ecb",
		wantCode: 0,
	}, {
		name:     "random key 5, sha256(0x05), rfc6979 nonce",
		key:      "915cb9ba4675de06a182088b182abcf79fa8ac989328212c6b866fa3ec2338f9",
		msg:      "05",
		hash:     "e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db",
		nonce:    "7d294918d3737f3b8b02585a4aae095395559ec93e09dc8131b45d669ac8fd1b",
		rfc6979:  true,
		wantSigR: "2e11d1671d1d2c5a669cfdff0a99bb4145101abf02811ef8a4d52cba73c1824f",
		wantSigS: "5e84c656555ffdc9d495939e0b230cd9ef9ede0e4cd000ded72ecbcdcbd21825",
		wantCode: 0,
	}, {
		name:     "random key 6, sha256(0x06), rfc6979 nonce",
		key:      "93e9d81d818f08ba1f850c6dfb82256b035b42f7d43c1fe090804fb009aca441",
		msg:      "06",
		hash:     "67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6",
		nonce:    "c85ff40da56d4c5b7d6a994cce7bfb989cbe3aea322039ad9778a3e2837dd6bb",
		rfc6979:  true,
		wantSigR: "e78880dadcd8d090018854a46d2e114bcb3e45063ffb8cda1d5c75003a3f9c59",
		wantSigS: "773c11abb814d1d011897a061fdf259073a67377bc48a7ee4a7e15047f734790",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 7, sha256(0x07), rfc6979 nonce",
		key:      "c249bbd5f533672b7dcd514eb1256854783531c2b85fe60bf4ce6ea1f26afc2b",
		msg:      "07",
		hash:     "ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879",
		nonce:    "8462d760475e6ea4143694c2dd4dd866e907b6d725388a164db1cc0d17b2039d",
		rfc6979:  true,
		wantSigR: "df7e42ec34eacb93da860bdd65b45b8db000e73ee58fa47924d796de20b03321",
		wantSigS: "082b4f65bd7290c27c78d66eeda09ed546a9d84a526c12accec581610a223e58",
		wantCode: 0,
	}, {
		name:     "random key 8, sha256(0x08), rfc6979 nonce",
		key:      "ec0be92fcec66cf1f97b5c39f83dfd4ddcad0dad468d3685b5eec556c6290bcc",
		msg:      "08",
		hash:     "beead77994cf573341ec17b58bbf7eb34d2711c993c1d976b128b3188dc1829a",
		nonce:    "31ea25a68a8be460734649fa4c8e237d121e90d506d97c15e6fd8ffbad21ed8b",
		rfc6979:  true,
		wantSigR: "bafcbfc24c4639923942700ca20be26911c3c6784ab862a32c5cd4c9e2a44607",
		wantSigS: "1e55ef49cf412258e355b762adbd65ab0e48bfaabc0e8fa2b033e544812a60bd",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}, {
		name:     "random key 9, sha256(0x09), rfc6979 nonce",
		key:      "6847b071a7cba6a85099b26a9c3e57a964e4990620e1e1c346fecc4472c4d834",
		msg:      "09",
		hash:     "2b4c342f5433ebe591a1da77e013d1b72475562d48578dca8b84bac6651c3cb9",
		nonce:    "c1dae7fc60d4b06dc9a1bab3479b2871ec42404168bb8b6bc9a99ec1d2b55c4e",
		rfc6979:  true,
		wantSigR: "7d16755df5b184c43e4c34dce670ad238a19a2d40aa857c3a9ffb4d01915ac1c",
		wantSigS: "77d345e51bdab5f07c99400c36a5d0547b5d04d016e8a2bc7559ef613b57894f",
		wantCode: 0,
	}, {
		name:     "random key 10, sha256(0x0a), rfc6979 nonce",
		key:      "b7548540f52fe20c161a0d623097f827608c56023f50442cc00cc50ad674f6b5",
		msg:      "0a",
		hash:     "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
		nonce:    "6e3033e7f9799ca5d02f991c3139bc1201ff46e5ae735ee9386bcf65e700c457",
		rfc6979:  true,
		wantSigR: "731ee8d5dd0f677684b30e8cd34ecc2708e026a4c40277b42334bfbd887b6ba1",
		wantSigS: "38474db7b3a4cd5cabbdc54599811747144ce18e6dcfaadb0702453bc06a17d3",
		wantCode: pubKeyRecoveryCodeOddnessBit,
	}}

	// Ensure the test data is sane by comparing the provided hashed message and
	// nonce, in the case RFC6979 was used, to their calculated values.  These
	// values could just be calculated instead of specified in the test data,
	// but it's nice to have all of the calculated values available in the test
	// data for cross implementation testing and verification.
	for _, test := range tests {
		msg := hexToBytes(test.msg)
		hash := hexToBytes(test.hash)

		calcHash := sha256.Sum256(msg)
		if !bytes.Equal(calcHash[:], hash) {
			t.Errorf("%s: mismatched test hash -- expected: %x, given: %x",
				test.name, calcHash[:], hash)
			continue
		}
		if test.rfc6979 {
			privKeyBytes := hexToBytes(test.key)
			nonceBytes := hexToBytes(test.nonce)
			var calcNonce secp256k1.ModNScalar
			secp256k1.NonceRFC6979(&calcNonce, privKeyBytes, hash, nil, nil, 0)
			calcNonceBytes := calcNonce.Bytes()
			if !bytes.Equal(calcNonceBytes[:], nonceBytes) {
				t.Errorf("%s: mismatched test nonce -- expected: %x, given: %x",
					test.name, calcNonceBytes, nonceBytes)
				continue
			}
		}
	}

	return tests
}

// TestSignAndVerify ensures the ECDSA signing function produces the expected
// signatures for a selected set of private keys, messages, and nonces that have
// been verified independently with the Sage computer algebra system.  It also
// ensures verifying the signature works as expected.
func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	tests := signTests(t)
	for _, test := range tests {
		privKey := secp256k1.NewPrivateKey(hexToModNScalar(test.key))
		hash := hexToBytes(test.hash)
		nonce := hexToModNScalar(test.nonce)
		wantSigR := hexToModNScalar(test.wantSigR)
		wantSigS := hexToModNScalar(test.wantSigS)
		wantSig := NewSignature(wantSigR, wantSigS).Serialize()

		// Sign the hash of the message with the given private key and nonce.
		var gotSig Signature
		recoveryCode, success := sign(&gotSig, &privKey.Key, nonce, hash)
		if !success {
			t.Errorf("%s: unexpected error when signing", test.name)
			continue
		}

		// Ensure the generated signature is the expected value.
		gotSigBytes := gotSig.Serialize()
		if !bytes.Equal(gotSigBytes, wantSig) {
			t.Errorf("%s: unexpected signature -- got %x, want %x", test.name,
				gotSigBytes, wantSig)
			continue
		}

		// Ensure the generated public key recovery code is the expected value.
		if recoveryCode != test.wantCode {
			t.Errorf("%s: unexpected recovery code -- got %x, want %x",
				test.name, recoveryCode, test.wantCode)
			continue
		}

		// Ensure the R method returns the expected value.
		gotSigR := gotSig.R()
		if !gotSigR.Equals(wantSigR) {
			t.Errorf("%s: unexpected R component -- got %064x, want %064x",
				test.name, gotSigR.Bytes(), wantSigR.Bytes())
		}

		// Ensure the S method returns the expected value.
		gotSigS := gotSig.S()
		if !gotSigS.Equals(wantSigS) {
			t.Errorf("%s: unexpected S component -- got %064x, want %064x",
				test.name, gotSigS.Bytes(), wantSigS.Bytes())
		}

		// Ensure the produced signature verifies.
		pubKey := privKey.PubKey()
		if !gotSig.Verify(hash, pubKey) {
			t.Errorf("%s: signature failed to verify", test.name)
			continue
		}

		// Ensure the signature generated by the exported method is the expected
		// value as well in the case RFC6979 was used.
		if test.rfc6979 {
			var gotSig Signature
			Sign(&gotSig, privKey, hash)
			gotSigBytes := gotSig.Serialize()
			if !bytes.Equal(gotSigBytes, wantSig) {
				t.Errorf("%s: unexpected signature -- got %x, want %x",
					test.name, gotSigBytes, wantSig)
				continue
			}
		}
	}
}

// TestSignAndVerifyRandom ensures ECDSA signing and verification work as
// expected for randomly-generated private keys and messages.  It also ensures
// invalid signatures are not improperly verified by mutating the valid
// signature and changing the message the signature covers.
func TestSignAndVerifyRandom(t *testing.T) {
	t.Parallel()

	// Use a unique random seed each test instance and log it if the tests fail.
	seed := time.Now().Unix()
	rng := rand.New(rand.NewSource(seed))
	defer func(t *testing.T, seed int64) {
		if t.Failed() {
			t.Logf("random seed: %d", seed)
		}
	}(t, seed)

	for i := 0; i < 100; i++ {
		// Generate a random private key.
		var buf [32]byte
		if _, err := rng.Read(buf[:]); err != nil {
			t.Fatalf("failed to read random private key: %v", err)
		}
		var privKeyScalar secp256k1.ModNScalar
		privKeyScalar.SetBytes(&buf)
		privKey := secp256k1.NewPrivateKey(&privKeyScalar)

		// Generate a random hash to sign.
		var hash [32]byte
		if _, err := rng.Read(hash[:]); err != nil {
			t.Fatalf("failed to read random hash: %v", err)
		}

		// Sign the hash with the private key and then ensure the produced
		// signature is valid for the hash and public key associated with the
		// private key.
		var sig Signature
		Sign(&sig, privKey, hash[:])
		pubKey := privKey.PubKey()
		if !sig.Verify(hash[:], pubKey) {
			t.Fatalf("failed to verify signature\nsig: %x\nhash: %x\n"+
				"private key: %x\npublic key: %x", sig.Serialize(), hash,
				privKey.Serialize(), pubKey.SerializeCompressed())
		}

		// Change a random bit in the signature and ensure the bad signature
		// fails to verify the original message.
		badSig := sig
		randByte := rng.Intn(32)
		randBit := rng.Intn(7)
		if randComponent := rng.Intn(2); randComponent == 0 {
			badSigBytes := badSig.Rs.Bytes()
			badSigBytes[randByte] ^= 1 << randBit
			badSig.Rs.SetBytes(&badSigBytes)
		} else {
			badSigBytes := badSig.Ss.Bytes()
			badSigBytes[randByte] ^= 1 << randBit
			badSig.Ss.SetBytes(&badSigBytes)
		}
		if badSig.Verify(hash[:], pubKey) {
			t.Fatalf("verified bad signature\nsig: %x\nhash: %x\n"+
				"private key: %x\npublic key: %x", badSig.Serialize(), hash,
				privKey.Serialize(), pubKey.SerializeCompressed())
		}

		// Change a random bit in the hash that was originally signed and ensure
		// the original good signature fails to verify the new bad message.
		badHash := make([]byte, len(hash))
		copy(badHash, hash[:])
		randByte = rng.Intn(len(badHash))
		randBit = rng.Intn(7)
		badHash[randByte] ^= 1 << randBit
		if sig.Verify(badHash, pubKey) {
			t.Fatalf("verified signature for bad hash\nsig: %x\nhash: %x\n"+
				"pubkey: %x", sig.Serialize(), badHash,
				pubKey.SerializeCompressed())
		}
	}
}

// TestSignFailures ensures the internal ECDSA signing function returns an
// unsuccessful result when particular combinations of values are unable to
// produce a valid signature.
func TestSignFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string // test description
		key   string // hex encoded private key
		hash  string // hex encoded hash of the message to sign
		nonce string // hex encoded nonce to use in the signature calculation
	}{{
		name:  "zero R is invalid (forced by using zero nonce)",
		key:   "0000000000000000000000000000000000000000000000000000000000000001",
		hash:  "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		nonce: "0000000000000000000000000000000000000000000000000000000000000000",
	}, {
		name:  "zero S is invalid (forced by key/hash/nonce choice)",
		key:   "0000000000000000000000000000000000000000000000000000000000000001",
		hash:  "393bec84f1a04037751c0d6c2817f37953eaa204ac0898de7adb038c33a20438",
		nonce: "4154324ecd4158938f1df8b5b659aeb639c7fbc36005934096e514af7d64bcc2",
	}}

	for _, test := range tests {
		privKey := hexToModNScalar(test.key)
		hash := hexToBytes(test.hash)
		nonce := hexToModNScalar(test.nonce)

		// Ensure the signing is NOT successful.
		var sig Signature
		_, success := sign(&sig, privKey, nonce, hash)
		if success {
			t.Errorf("%s: unexpected success -- got sig %x", test.name,
				sig.Serialize())
			continue
		}
	}
}

// TestVerifyFailures ensures the ECDSA verification function returns an
// unsuccessful result for edge conditions.
func TestVerifyFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string // test description
		key  string // hex encoded private key
		hash string // hex encoded hash of the message to sign
		r, s string // hex encoded r and s components of signature to verify
	}{{
		name: "signature R is 0",
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "0000000000000000000000000000000000000000000000000000000000000000",
		s:    "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
	}, {
		name: "signature S is 0",
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09",
		s:    "0000000000000000000000000000000000000000000000000000000000000000",
	}, {
		name: "u1G + u2Q is the point at infinity",
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "3cfe45621a29fac355260a14b9adc0fe43ac2f13e918fc9ddfa117e964b61a8a",
		s:    "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
	}, {
		name: "signature R < P-N, but invalid",
		key:  "0000000000000000000000000000000000000000000000000000000000000001",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		r:    "000000000000000000000000000000014551231950b75fc4402da1722fc9baed",
		s:    "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560",
	}}

	for _, test := range tests {
		privKey := hexToModNScalar(test.key)
		hash := hexToBytes(test.hash)
		r := hexToModNScalar(test.r)
		s := hexToModNScalar(test.s)
		sig := NewSignature(r, s)

		// Ensure the verification is NOT successful.
		pubKey := secp256k1.NewPrivateKey(privKey).PubKey()
		if sig.Verify(hash, pubKey) {
			t.Errorf("%s: unexpected success for invalid signature: %x",
				test.name, sig.Serialize())
			continue
		}
	}
}

// TestSignatureIsEqual ensures that equality testing between two signatures
// works as expected.
func TestSignatureIsEqual(t *testing.T) {
	sig1 := &Signature{
		Rs: *hexToModNScalar("82235e21a2300022738dabb8e1bbd9d19cfb1e7ab8c30a23b0afbb8d178abcf3"),
		Ss: *hexToModNScalar("24bf68e256c534ddfaf966bf908deb944305596f7bdcc38d69acad7f9c868724"),
	}
	sig1Copy := &Signature{
		Rs: *hexToModNScalar("82235e21a2300022738dabb8e1bbd9d19cfb1e7ab8c30a23b0afbb8d178abcf3"),
		Ss: *hexToModNScalar("24bf68e256c534ddfaf966bf908deb944305596f7bdcc38d69acad7f9c868724"),
	}
	sig2 := &Signature{
		Rs: *hexToModNScalar("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41"),
		Ss: *hexToModNScalar("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"),
	}

	if !sig1.IsEqual(sig1) {
		t.Fatalf("bad self signature equality check: %v == %v", sig1, sig1Copy)
	}
	if !sig1.IsEqual(sig1Copy) {
		t.Fatalf("bad signature equality check: %v == %v", sig1, sig1Copy)
	}

	if sig1.IsEqual(sig2) {
		t.Fatalf("bad signature equality check: %v != %v", sig1, sig2)
	}
}

// TestSignAndRecoverCompact ensures compact (recoverable public key) ECDSA
// signing and public key recovery works as expected for a selected set of
// private keys, messages, and nonces that have been verified independently with
// the Sage computer algebra system.
func TestSignAndRecoverCompact(t *testing.T) {
	t.Parallel()

	tests := signTests(t)
	for _, test := range tests {
		// Skip tests using nonces that are not RFC6979.
		if !test.rfc6979 {
			continue
		}

		// Parse test data.
		privKey := secp256k1.NewPrivateKey(hexToModNScalar(test.key))
		pubKey := privKey.PubKey()
		hash := hexToBytes(test.hash)
		wantSig := hexToBytes("00" + test.wantSigR + test.wantSigS)

		// Test compact signatures for both the compressed and uncompressed
		// versions of the public key.
		for _, compressed := range []bool{true, false} {
			// Populate the expected compact signature recovery code.
			wantRecoveryCode := compactSigMagicOffset + test.wantCode
			if compressed {
				wantRecoveryCode += compactSigCompPubKey
			}
			wantSig[0] = wantRecoveryCode

			// Sign the hash of the message with the given private key and
			// ensure the generated signature is the expected value per the
			// specified compressed flag.
			gotSig := SignCompact(privKey, hash, compressed)
			if !bytes.Equal(gotSig, wantSig) {
				t.Errorf("%s: unexpected signature -- got %x, want %x",
					test.name, gotSig, wantSig)
				continue
			}

			// Ensure the recovered public key and flag that indicates whether
			// or not the signature was for a compressed public key are the
			// expected values.
			gotPubKey, gotCompressed, err := RecoverCompact(gotSig, hash)
			if err != nil {
				t.Errorf("%s: unexpected error when recovering: %v", test.name,
					err)
				continue
			}
			if gotCompressed != compressed {
				t.Errorf("%s: unexpected compressed flag -- got %v, want %v",
					test.name, gotCompressed, compressed)
				continue
			}
			if !gotPubKey.IsEqual(pubKey) {
				t.Errorf("%s: unexpected public key -- got %x, want %x",
					test.name, gotPubKey.SerializeUncompressed(),
					pubKey.SerializeUncompressed())
				continue
			}
		}
	}
}

// TestRecoverCompactErrors ensures several error paths in compact signature
// recovery are detected as expected.  When possible, the signatures are
// otherwise valid with the exception of the specific failure to ensure it's
// robust against things like fault attacks.
func TestRecoverCompactErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string // test description
		sig  string // hex encoded signature to recover pubkey from
		hash string // hex encoded hash of message
		err  error  // expected error
	}{{
		name: "empty signature",
		sig:  "",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigInvalidLen,
	}, {
		// Signature created from private key 0x02, sha256(0x01020304).
		name: "no compact sig recovery code (otherwise valid sig)",
		sig: "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigInvalidLen,
	}, {
		// Signature created from private key 0x02, sha256(0x01020304).
		name: "signature one byte too long (S padded with leading zero)",
		sig: "1f" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"0044b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigInvalidLen,
	}, {
		// Signature created from private key 0x02, sha256(0x01020304).
		name: "compact sig recovery code too low (otherwise valid sig)",
		sig: "1a" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigInvalidRecoveryCode,
	}, {
		// Signature created from private key 0x02, sha256(0x01020304).
		name: "compact sig recovery code too high (otherwise valid sig)",
		sig: "23" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigInvalidRecoveryCode,
	}, {
		// Signature invented since finding a signature with an r value that is
		// exactly the group order prior to the modular reduction is not
		// calculable without breaking the underlying crypto.
		name: "R == group order",
		sig: "1f" +
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigRTooBig,
	}, {
		// Signature invented since finding a signature with an r value that
		// would be valid modulo the group order and is still 32 bytes is not
		// calculable without breaking the underlying crypto.
		name: "R > group order and still 32 bytes (order + 1)",
		sig: "1f" +
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigRTooBig,
	}, {
		// Signature invented since the only way a signature could have an r
		// value of zero is if the nonce were zero which is invalid.
		name: "R == 0",
		sig: "1f" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigRIsZero,
	}, {
		// Signature invented since finding a signature with an s value that is
		// exactly the group order prior to the modular reduction is not
		// calculable without breaking the underlying crypto.
		name: "S == group order",
		sig: "1f" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigSTooBig,
	}, {
		// Signature invented since finding a signature with an s value that
		// would be valid modulo the group order and is still 32 bytes is not
		// calculable without breaking the underlying crypto.
		name: "S > group order and still 32 bytes (order + 1)",
		sig: "1f" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigSTooBig,
	}, {
		// Signature created by forcing the key/hash/nonce choices such that s
		// is zero and is therefore invalid.  The signing code will not produce
		// such a signature in practice.
		name: "S == 0",
		sig: "1f" +
			"e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59" +
			"0000000000000000000000000000000000000000000000000000000000000000",
		hash: "393bec84f1a04037751c0d6c2817f37953eaa204ac0898de7adb038c33a20438",
		err:  ErrSigSIsZero,
	}, {
		// Signature invented since finding a private key needed to create a
		// valid signature with an r value that is >= group order prior to the
		// modular reduction is not possible without breaking the underlying
		// crypto.
		name: "R >= field prime minus group order with overflow bit",
		sig: "21" +
			"000000000000000000000000000000014551231950b75fc4402da1722fc9baee" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrSigOverflowsPrime,
	}, {
		// Signature invented since finding a private key needed to create a
		// valid signature with an r value that is > group order prior to the
		// modular reduction is not possible without breaking the underlying
		// crypto.
		name: "R > group order with overflow bit",
		sig: "21" +
			"000000000000000000000000000000014551231950b75fc4402da1722fc9baed" +
			"44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrPointNotOnCurve,
	}, {
		// Signature created from private key 0x01, sha256(0x0102030407) over
		// the secp256r1 curve (note the r1 instead of k1).
		name: "pubkey not on the curve, signature valid for secp256r1 instead",
		sig: "1f" +
			"2a81d1b3facc22185267d3f8832c5104902591bc471253f1cfc5eb25f4f740f2" +
			"72e65d019f9b09d769149e2be0b55de9b0224d34095bddc6a5dba90bfda33c45",
		hash: "9165e957708bc95cf62d020769c150b2d7b08e7ab7981860815b1eaabd41d695",
		err:  ErrPointNotOnCurve,
	}, {
		// Signature created from private key 0x01, sha256(0x01020304) and
		// manually setting s = -e*k^-1.
		name: "calculated pubkey point at infinity",
		sig: "1f" +
			"c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09" +
			"1281d8d90a5774045abd57b453c7eadbc830dbadec89ae8dd7639b9cc55641d0",
		hash: "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7",
		err:  ErrPointNotOnCurve,
	}}

	for _, test := range tests {
		// Parse test data.
		hash := hexToBytes(test.hash)
		sig := hexToBytes(test.sig)

		// Ensure the expected error is hit.
		_, _, err := RecoverCompact(sig, hash)
		if !errors.Is(err, test.err) {
			t.Errorf("%s: mismatched err -- got %v, want %v", test.name, err,
				test.err)
			continue
		}
	}
}

// TestSignAndRecoverCompactRandom ensures compact (recoverable public key)
// ECDSA signing and recovery work as expected for randomly-generated private
// keys and messages.  It also ensures mutated signatures and messages do not
// improperly recover the original public key.
func TestSignAndRecoverCompactRandom(t *testing.T) {
	t.Parallel()

	// Use a unique random seed each test instance and log it if the tests fail.
	seed := time.Now().Unix()
	rng := rand.New(rand.NewSource(seed))
	defer func(t *testing.T, seed int64) {
		if t.Failed() {
			t.Logf("random seed: %d", seed)
		}
	}(t, seed)

	for i := 0; i < 100; i++ {
		// Generate a random private key.
		var buf [32]byte
		if _, err := rng.Read(buf[:]); err != nil {
			t.Fatalf("failed to read random private key: %v", err)
		}
		var privKeyScalar secp256k1.ModNScalar
		privKeyScalar.SetBytes(&buf)
		privKey := secp256k1.NewPrivateKey(&privKeyScalar)
		wantPubKey := privKey.PubKey()

		// Generate a random hash to sign.
		var hash [32]byte
		if _, err := rng.Read(hash[:]); err != nil {
			t.Fatalf("failed to read random hash: %v", err)
		}

		// Test compact signatures for both the compressed and uncompressed
		// versions of the public key.
		for _, compressed := range []bool{true, false} {
			// Sign the hash with the private key and then ensure the original
			// public key and compressed flag is recovered from the produced
			// signature.
			gotSig := SignCompact(privKey, hash[:], compressed)

			gotPubKey, gotCompressed, err := RecoverCompact(gotSig, hash[:])
			if err != nil {
				t.Fatalf("unexpected err: %v\nsig: %x\nhash: %x\nprivate key: %x",
					err, gotSig, hash, privKey.Serialize())
			}
			if gotCompressed != compressed {
				t.Fatalf("unexpected compressed flag: %v\nsig: %x\nhash: %x\n"+
					"private key: %x", gotCompressed, gotSig, hash,
					privKey.Serialize())
			}
			if !gotPubKey.IsEqual(wantPubKey) {
				t.Fatalf("unexpected recovered public key: %x\nsig: %x\nhash: "+
					"%x\nprivate key: %x", gotPubKey.SerializeUncompressed(),
					gotSig, hash, privKey.Serialize())
			}

			// Change a random bit in the signature and ensure the bad signature
			// fails to recover the original public key.
			badSig := make([]byte, len(gotSig))
			copy(badSig, gotSig)
			randByte := rng.Intn(len(badSig)-1) + 1
			randBit := rng.Intn(7)
			badSig[randByte] ^= 1 << randBit
			badPubKey, _, err := RecoverCompact(badSig, hash[:])
			if err == nil && badPubKey.IsEqual(wantPubKey) {
				t.Fatalf("recovered public key for bad sig: %x\nhash: %x\n"+
					"private key: %x", badSig, hash, privKey.Serialize())
			}

			// Change a random bit in the hash that was originally signed and
			// ensure the original good signature fails to recover the original
			// public key.
			badHash := make([]byte, len(hash))
			copy(badHash, hash[:])
			randByte = rng.Intn(len(badHash))
			randBit = rng.Intn(7)
			badHash[randByte] ^= 1 << randBit
			badPubKey, _, err = RecoverCompact(gotSig, badHash)
			if err == nil && badPubKey.IsEqual(wantPubKey) {
				t.Fatalf("recovered public key for bad hash: %x\nsig: %x\n"+
					"private key: %x", badHash, gotSig, privKey.Serialize())
			}
		}
	}
}
