//go:build cgo

package binding

/*
#cgo CFLAGS: -I${SRCDIR}/secp256k1_c/include -O2

#cgo noescape secp256k1_ec_pubkey_parse
#cgo nocallback secp256k1_ec_pubkey_parse
#cgo noescape secp256k1_keypair_create
#cgo nocallback secp256k1_keypair_create
#cgo noescape secp256k1_schnorrsig_sign_custom
#cgo nocallback secp256k1_schnorrsig_sign_custom
#cgo noescape secp256k1_xonly_pubkey_from_pubkey
#cgo nocallback secp256k1_xonly_pubkey_from_pubkey
#cgo noescape secp256k1_schnorrsig_verify
#cgo nocallback secp256k1_schnorrsig_verify

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
	"unsafe"
)

var ctx *C.secp256k1_context

func init() {
	ctx = C.secp256k1_context_create(C.SECP256K1_CONTEXT_NONE)
}

type PrivateKey struct {
	K [32]byte
}

func PrivateNegate(priv *PrivateKey) {
	C.secp256k1_ec_seckey_negate(ctx,
		(*C.uchar)(unsafe.Pointer(&priv.K[0])))
}

type PublicKey struct {
	P C.secp256k1_pubkey
}

func PublicKeyParse33(pub *PublicKey, data []byte) error {
	ok := C.secp256k1_ec_pubkey_parse(ctx, &pub.P,
		(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(33))
	if ok == 0 {
		return fmt.Errorf("error parsing public key")
	}
	return nil
}

func PublicKeyParse65(pub *PublicKey, data []byte) error {
	ok := C.secp256k1_ec_pubkey_parse(ctx, &pub.P,
		(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(65))
	if ok == 0 {
		return fmt.Errorf("error parsing public key")
	}
	return nil
}

func PublicKeySerialize33(data []byte, pub *PublicKey) {
	dlen := 33
	C.secp256k1_ec_pubkey_serialize(ctx,
		(*C.uchar)(unsafe.Pointer(&data[0])),
		(*C.size_t)(unsafe.Pointer(&dlen)),
		&pub.P, C.SECP256K1_EC_COMPRESSED)
}

func PublicKeySerialize65(data []byte, pub *PublicKey) {
	dlen := 65
	C.secp256k1_ec_pubkey_serialize(ctx,
		(*C.uchar)(unsafe.Pointer(&data[0])),
		(*C.size_t)(unsafe.Pointer(&dlen)),
		&pub.P, C.SECP256K1_EC_UNCOMPRESSED)
}

func PublicKeyCreate(pub *PublicKey, priv *PrivateKey) error {
	ok := C.secp256k1_ec_pubkey_create(ctx, &pub.P,
		(*C.uchar)(unsafe.Pointer(&priv.K[0])))
	if ok == 0 {
		return fmt.Errorf(
			"failed to derive public key from private key")
	}
	return nil
}

type ECDSASignature struct {
	S C.secp256k1_ecdsa_signature
}

func ECDSASignatureParseCompact(sig *ECDSASignature,
	data []byte) error {

	ok := C.secp256k1_ecdsa_signature_parse_compact(ctx, &sig.S,
		(*C.uchar)(unsafe.Pointer(&data[0])))
	if ok == 0 {
		return fmt.Errorf("failed to parse signature")
	}
	return nil
}

func ECDSASignatureSerializeCompact(data []byte, sig *ECDSASignature) {
	C.secp256k1_ecdsa_signature_serialize_compact(ctx,
		(*C.uchar)(unsafe.Pointer(&data[0])), &sig.S)
}

func ECDSASign(sig *ECDSASignature, hash []byte,
	priv *PrivateKey) error {

	ok := C.secp256k1_ecdsa_sign(ctx, &sig.S,
		(*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.uchar)(unsafe.Pointer(&priv.K[0])),
		C.secp256k1_nonce_function_rfc6979,
		unsafe.Pointer(nil))
	if ok == 0 {
		return fmt.Errorf("failed to sign")
	}
	return nil
}

func ECDSAVerify(sig *ECDSASignature, hash []byte,
	pub *PublicKey) bool {

	ok := C.secp256k1_ecdsa_verify(ctx, &sig.S,
		(*C.uchar)(unsafe.Pointer(&hash[0])), &pub.P)
	return ok == 1
}

type SchnorrSignature struct {
	S [64]byte
}

func SchnorrSign(sig *SchnorrSignature, msg []byte,
	priv *PrivateKey, auxRand *[32]byte) error {

	msgP := (*byte)(nil)
	msgLen := len(msg)
	if msgLen != 0 {
		msgP = &msg[0]
	}

	var kp C.secp256k1_keypair
	defer func() {
		var kpZr C.secp256k1_keypair
		kp = kpZr
	}()
	ok := C.secp256k1_keypair_create(ctx, &kp,
		(*C.uchar)(unsafe.Pointer(&priv.K[0])))
	if ok == 0 {
		return fmt.Errorf("failed to create keypair")
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
			(*C.uchar)(unsafe.Pointer(&sig.S[0])),
			(*C.uchar)(unsafe.Pointer(msgP)), C.size_t(msgLen),
			&kp,
			extraParamsP)
		pinner.Unpin()
		if ok == 0 {
			return fmt.Errorf("failed to sign with auxRand")
		}
		return nil
	}

	ok = C.secp256k1_schnorrsig_sign_custom(ctx,
		(*C.uchar)(unsafe.Pointer(&sig.S[0])),
		(*C.uchar)(unsafe.Pointer(msgP)), C.size_t(msgLen), &kp,
		(*C.secp256k1_schnorrsig_extraparams)(unsafe.Pointer(nil)))
	if ok == 0 {
		return fmt.Errorf("failed to sign")
	}
	return nil
}

func SchnorrVerify(sig *SchnorrSignature, pub *PublicKey,
	msg []byte) bool {

	var xonlyPub C.secp256k1_xonly_pubkey
	ok := C.secp256k1_xonly_pubkey_from_pubkey(ctx, &xonlyPub,
		(*C.int)(unsafe.Pointer(nil)), &pub.P)
	if ok == 0 {
		return false
	}

	msgP := (*byte)(nil)
	msgLen := len(msg)
	if msgLen != 0 {
		msgP = &msg[0]
	}

	ok = C.secp256k1_schnorrsig_verify(ctx,
		(*C.uchar)(unsafe.Pointer(&sig.S[0])),
		(*C.uchar)(unsafe.Pointer(msgP)), C.size_t(msgLen),
		&xonlyPub)
	if ok == 0 {
		return false
	}
	return true
}
