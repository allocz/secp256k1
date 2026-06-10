package secp

/*
#cgo CFLAGS: -I${SRCDIR}/secp256k1_c/include -O2
#cgo noescape secp256k1_ec_pubkey_parse
#cgo nocallback secp256k1_ec_pubkey_parse
#cgo noescape secp256k1_keypair_create
#cgo nocallback secp256k1_keypair_create
#cgo noescape secp256k1_schnorrsig_sign_custom
#cgo nocallback secp256k1_schnorrsig_sign_custom

#include "secp256k1_c/src/secp256k1.c"
#include "secp256k1_c/src/modules/extrakeys/main_impl.h"
#include "secp256k1_c/src/modules/schnorrsig/main_impl.h"
#include "secp256k1_c/src/precomputed_ecmult_gen.c"
#include "secp256k1_c/src/precomputed_ecmult.c"
#include "secp256k1.h"
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"
*/
import "C"
import (
	"fmt"
	"runtime"
	"slices"
	"unsafe"
)

var ctx *C.secp256k1_context

func init() {
	ctx = C.secp256k1_context_create(C.SECP256K1_CONTEXT_NONE)
}

type PrivateKey struct {
	k [32]byte
}

func PrivateKeyFromBytes(priv *PrivateKey, data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid private key length")
	}
	ok := C.secp256k1_ec_seckey_verify(ctx,
		(*C.uchar)(unsafe.Pointer(&data[0])))
	if ok == 0 {
		return fmt.Errorf("invalid private key")
	}
	copy(priv.k[0:], data)
	return nil
}

func PrivateKeyToBytes(data []byte, priv *PrivateKey) {
	copy(data[0:], priv.k[:])
}

type PublicKey struct {
	p C.secp256k1_pubkey
}

func PublicKeyFromBytes(pub *PublicKey, data []byte) error {
	ok := C.secp256k1_ec_pubkey_parse(ctx, &pub.p,
		(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if ok == 0 {
		return fmt.Errorf("fail to parse pubkey")
	}
	return nil
}

func PublicKeyToBytes(data []byte, pub *PublicKey) {
	data[0] = 0x04

	wsrc := (*[8][8]byte)(unsafe.Pointer(&pub.p))
	w := (*[8][8]byte)(unsafe.Pointer(&data[1]))
	w[0] = wsrc[3]
	w[1] = wsrc[2]
	w[2] = wsrc[1]
	w[3] = wsrc[0]
	w[4] = wsrc[7]
	w[5] = wsrc[6]
	w[6] = wsrc[5]
	w[7] = wsrc[4]

	slices.Reverse(w[0][:])
	slices.Reverse(w[1][:])
	slices.Reverse(w[2][:])
	slices.Reverse(w[3][:])
	slices.Reverse(w[4][:])
	slices.Reverse(w[5][:])
	slices.Reverse(w[6][:])
	slices.Reverse(w[7][:])
}

func PublicKeyFromPrivateKey(pub *PublicKey, priv *PrivateKey) {
	ok := C.secp256k1_ec_pubkey_create(ctx, &pub.p,
		(*C.uchar)(unsafe.Pointer(&priv.k[0])))
	if ok == 0 {
		panic("failed to derive pubkey from privkey")
	}
}

type ECDSASignature struct {
	s C.secp256k1_ecdsa_signature
}

func ECDSASignatureFromBytes(sig *ECDSASignature, data []byte) error {
	if len(data) != 64 {
		return fmt.Errorf("wrong signature size")
	}
	ok := C.secp256k1_ecdsa_signature_parse_compact(ctx, &sig.s,
		(*C.uchar)(unsafe.Pointer(&data[0])))
	if ok == 0 {
		return fmt.Errorf("could not parse signature")
	}
	return nil
}

func ECDSASignatureToBytes(data []byte, sig *ECDSASignature) {
	C.secp256k1_ecdsa_signature_serialize_compact(ctx,
		(*C.uchar)(unsafe.Pointer(&data[0])), &sig.s)
}

func ECDSASign(sig *ECDSASignature, priv *PrivateKey, hash []byte) error {
	if len(hash) != 32 {
		return fmt.Errorf("invalid hash length")
	}
	ok := C.secp256k1_ecdsa_sign(ctx, &sig.s,
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.uchar)(unsafe.Pointer(&priv.k[0])),
		C.secp256k1_nonce_function_rfc6979,
		unsafe.Pointer(nil))
	if ok == 0 {
		return fmt.Errorf("signing failed")
	}
	return nil
}

func ECDSAVerify(sig *ECDSASignature, pub *PublicKey, hash []byte) bool {
	if len(hash) != 32 {
		return false
	}
	ok := C.secp256k1_ecdsa_verify(ctx, &sig.s,
		(*C.uchar)(unsafe.Pointer(&hash[0])), &pub.p)
	if ok == 0 {
		return false
	}
	return true
}

type SchnorrSignature struct {
	s [64]byte
}

func SchnorrKeyPairFromBytes(priv *PrivateKey, pub *PublicKey,
	data []byte) error {

	err := PrivateKeyFromBytes(priv, data)
	if err != nil {
		return err
	}
	PublicKeyFromPrivateKey(pub, priv)
	var pubb [65]byte
	PublicKeyToBytes(pubb[:], pub)
	if pubb[64]&0x01 != 0 {
		var priv = *priv
		C.secp256k1_ec_seckey_negate(ctx,
			(*C.uchar)(unsafe.Pointer(&priv.k[0])))

		PublicKeyFromPrivateKey(pub, &priv)
	}
	return nil
}

func SchnorrPublicKeyFromBytes(pub *PublicKey, data []byte) error {
	var pubb [33]byte
	pubb[0] = 0x02
	copy(pubb[1:], data)
	ok := C.secp256k1_ec_pubkey_parse(ctx, &pub.p,
		(*C.uchar)(unsafe.Pointer(&pubb)), C.size_t(len(pubb)))
	if ok == 0 {
		return fmt.Errorf("fail to parse pubkey")
	}
	return nil
}

func SchnorrSignatureFromBytes(sig *SchnorrSignature, data []byte) error {
	copy(sig.s[:], data)
	return nil
}

func (s *SchnorrSignature) ToBytes(data []byte) []byte {
	copy(data, s.s[:])
	return data
}

func (s *SchnorrSignature) Verify(pub *PublicKey, msg []byte) bool {
	var xonlyPub C.secp256k1_xonly_pubkey
	ok := C.secp256k1_xonly_pubkey_from_pubkey(ctx, &xonlyPub,
		(*C.int)(unsafe.Pointer(nil)), &pub.p)
	if ok == 0 {
		return false
	}

	msgP := (*byte)(nil)
	msgLen := len(msg)
	if msgLen != 0 {
		msgP = &msg[0]
	}

	ok = C.secp256k1_schnorrsig_verify(ctx,
		(*C.uchar)(unsafe.Pointer(&s.s[0])),
		(*C.uchar)(unsafe.Pointer(msgP)), C.size_t(msgLen),
		&xonlyPub)
	if ok == 0 {
		return false
	}
	return true
}

func SchnorrSignExt(sig *SchnorrSignature, priv *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) error {

	msgP := (*byte)(nil)
	msgLen := len(msg)
	if msgLen != 0 {
		msgP = &msg[0]
	}

	var kp C.secp256k1_keypair
	ok := C.secp256k1_keypair_create(ctx, &kp,
		(*C.uchar)(unsafe.Pointer(&priv.k[0])))
	if ok == 0 {
		return fmt.Errorf("failed to create keypair from privkey")
	}

	if auxRand != nil {
		var extraParams C.secp256k1_schnorrsig_extraparams
		extraParamsP := &extraParams
		extraParamsP.magic = [4]C.uchar{0xda, 0x6f, 0xb3, 0x8c}
		extraParamsP.noncefp = C.secp256k1_nonce_function_hardened(
			unsafe.Pointer(nil))
		extraParamsP.ndata = unsafe.Pointer(&auxRand[0])

		var pinner runtime.Pinner
		pinner.Pin(extraParamsP.ndata)

		ok = C.secp256k1_schnorrsig_sign_custom(ctx,
			(*C.uchar)(unsafe.Pointer(&sig.s[0])),
			(*C.uchar)(unsafe.Pointer(msgP)), C.size_t(msgLen),
			&kp,
			extraParamsP)
		pinner.Unpin()
		if ok == 0 {
			return fmt.Errorf("signature failed")
		}
		return nil
	}

	ok = C.secp256k1_schnorrsig_sign_custom(ctx,
		(*C.uchar)(unsafe.Pointer(&sig.s[0])),
		(*C.uchar)(unsafe.Pointer(msgP)), C.size_t(msgLen), &kp,
		(*C.secp256k1_schnorrsig_extraparams)(unsafe.Pointer(nil)))
	if ok == 0 {
		return fmt.Errorf("signature failed")
	}

	return nil
}
