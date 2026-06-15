//go:build cgo

package secp

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
	k [32]byte
}

func PrivateKeyFromBytes(priv *PrivateKey, data []byte) error {
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

func publicKeyToBytesAmd64(data []byte, pub *PublicKey) {
	wsrc := (*[8]uint64)(unsafe.Pointer(&pub.p))

	data[0] = 0x04

	data[1] = byte((wsrc[3] >> (7 * 8)))
	data[2] = byte((wsrc[3] >> (6 * 8)))
	data[3] = byte((wsrc[3] >> (5 * 8)))
	data[4] = byte((wsrc[3] >> (4 * 8)))
	data[5] = byte((wsrc[3] >> (3 * 8)))
	data[6] = byte((wsrc[3] >> (2 * 8)))
	data[7] = byte((wsrc[3] >> (1 * 8)))
	data[8] = byte((wsrc[3] >> (0 * 8)))

	data[9] = byte((wsrc[2] >> (7 * 8)))
	data[10] = byte((wsrc[2] >> (6 * 8)))
	data[11] = byte((wsrc[2] >> (5 * 8)))
	data[12] = byte((wsrc[2] >> (4 * 8)))
	data[13] = byte((wsrc[2] >> (3 * 8)))
	data[14] = byte((wsrc[2] >> (2 * 8)))
	data[15] = byte((wsrc[2] >> (1 * 8)))
	data[16] = byte((wsrc[2] >> (0 * 8)))

	data[17] = byte((wsrc[1] >> (7 * 8)))
	data[18] = byte((wsrc[1] >> (6 * 8)))
	data[19] = byte((wsrc[1] >> (5 * 8)))
	data[20] = byte((wsrc[1] >> (4 * 8)))
	data[21] = byte((wsrc[1] >> (3 * 8)))
	data[22] = byte((wsrc[1] >> (2 * 8)))
	data[23] = byte((wsrc[1] >> (1 * 8)))
	data[24] = byte((wsrc[1] >> (0 * 8)))

	data[25] = byte((wsrc[0] >> (7 * 8)))
	data[26] = byte((wsrc[0] >> (6 * 8)))
	data[27] = byte((wsrc[0] >> (5 * 8)))
	data[28] = byte((wsrc[0] >> (4 * 8)))
	data[29] = byte((wsrc[0] >> (3 * 8)))
	data[30] = byte((wsrc[0] >> (2 * 8)))
	data[31] = byte((wsrc[0] >> (1 * 8)))
	data[32] = byte((wsrc[0] >> (0 * 8)))

	data[33] = byte((wsrc[7] >> (7 * 8)))
	data[34] = byte((wsrc[7] >> (6 * 8)))
	data[35] = byte((wsrc[7] >> (5 * 8)))
	data[36] = byte((wsrc[7] >> (4 * 8)))
	data[37] = byte((wsrc[7] >> (3 * 8)))
	data[38] = byte((wsrc[7] >> (2 * 8)))
	data[39] = byte((wsrc[7] >> (1 * 8)))
	data[40] = byte((wsrc[7] >> (0 * 8)))

	data[41] = byte((wsrc[6] >> (7 * 8)))
	data[42] = byte((wsrc[6] >> (6 * 8)))
	data[43] = byte((wsrc[6] >> (5 * 8)))
	data[44] = byte((wsrc[6] >> (4 * 8)))
	data[45] = byte((wsrc[6] >> (3 * 8)))
	data[46] = byte((wsrc[6] >> (2 * 8)))
	data[47] = byte((wsrc[6] >> (1 * 8)))
	data[48] = byte((wsrc[6] >> (0 * 8)))

	data[49] = byte((wsrc[5] >> (7 * 8)))
	data[50] = byte((wsrc[5] >> (6 * 8)))
	data[51] = byte((wsrc[5] >> (5 * 8)))
	data[52] = byte((wsrc[5] >> (4 * 8)))
	data[53] = byte((wsrc[5] >> (3 * 8)))
	data[54] = byte((wsrc[5] >> (2 * 8)))
	data[55] = byte((wsrc[5] >> (1 * 8)))
	data[56] = byte((wsrc[5] >> (0 * 8)))

	data[57] = byte((wsrc[4] >> (7 * 8)))
	data[58] = byte((wsrc[4] >> (6 * 8)))
	data[59] = byte((wsrc[4] >> (5 * 8)))
	data[60] = byte((wsrc[4] >> (4 * 8)))
	data[61] = byte((wsrc[4] >> (3 * 8)))
	data[62] = byte((wsrc[4] >> (2 * 8)))
	data[63] = byte((wsrc[4] >> (1 * 8)))
	data[64] = byte((wsrc[4] >> (0 * 8)))
}

func publicKeyToBytes(data []byte, pub *PublicKey) {
	dataLen := len(data)
	C.secp256k1_ec_pubkey_serialize(ctx,
		(*C.uchar)(unsafe.Pointer(&data[0])),
		(*C.size_t)(unsafe.Pointer(&dataLen)),
		&pub.p, C.SECP256K1_EC_UNCOMPRESSED)
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

func ecdsaSignatureFromBytes(sig *ECDSASignature, data []byte) error {
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

func ecdsaSignatureFromBytesAmd64(sig *ECDSASignature, data []byte) error {
	if len(data) != 64 {
		return fmt.Errorf("wrong signature size")
	}

	wsrc := (*[8]uint64)(unsafe.Pointer(&data[0]))
	wdest := (*[64]byte)(unsafe.Pointer(&sig.s))

	wdest[0] = byte((wsrc[3] >> (7 * 8)))
	wdest[1] = byte((wsrc[3] >> (6 * 8)))
	wdest[2] = byte((wsrc[3] >> (5 * 8)))
	wdest[3] = byte((wsrc[3] >> (4 * 8)))
	wdest[4] = byte((wsrc[3] >> (3 * 8)))
	wdest[5] = byte((wsrc[3] >> (2 * 8)))
	wdest[6] = byte((wsrc[3] >> (1 * 8)))
	wdest[7] = byte((wsrc[3] >> (0 * 8)))

	wdest[8] = byte((wsrc[2] >> (7 * 8)))
	wdest[9] = byte((wsrc[2] >> (6 * 8)))
	wdest[10] = byte((wsrc[2] >> (5 * 8)))
	wdest[11] = byte((wsrc[2] >> (4 * 8)))
	wdest[12] = byte((wsrc[2] >> (3 * 8)))
	wdest[13] = byte((wsrc[2] >> (2 * 8)))
	wdest[14] = byte((wsrc[2] >> (1 * 8)))
	wdest[15] = byte((wsrc[2] >> (0 * 8)))

	wdest[16] = byte((wsrc[1] >> (7 * 8)))
	wdest[17] = byte((wsrc[1] >> (6 * 8)))
	wdest[18] = byte((wsrc[1] >> (5 * 8)))
	wdest[19] = byte((wsrc[1] >> (4 * 8)))
	wdest[20] = byte((wsrc[1] >> (3 * 8)))
	wdest[21] = byte((wsrc[1] >> (2 * 8)))
	wdest[22] = byte((wsrc[1] >> (1 * 8)))
	wdest[23] = byte((wsrc[1] >> (0 * 8)))

	wdest[24] = byte((wsrc[0] >> (7 * 8)))
	wdest[25] = byte((wsrc[0] >> (6 * 8)))
	wdest[26] = byte((wsrc[0] >> (5 * 8)))
	wdest[27] = byte((wsrc[0] >> (4 * 8)))
	wdest[28] = byte((wsrc[0] >> (3 * 8)))
	wdest[29] = byte((wsrc[0] >> (2 * 8)))
	wdest[30] = byte((wsrc[0] >> (1 * 8)))
	wdest[31] = byte((wsrc[0] >> (0 * 8)))

	wdest[32] = byte((wsrc[7] >> (7 * 8)))
	wdest[33] = byte((wsrc[7] >> (6 * 8)))
	wdest[34] = byte((wsrc[7] >> (5 * 8)))
	wdest[35] = byte((wsrc[7] >> (4 * 8)))
	wdest[36] = byte((wsrc[7] >> (3 * 8)))
	wdest[37] = byte((wsrc[7] >> (2 * 8)))
	wdest[38] = byte((wsrc[7] >> (1 * 8)))
	wdest[39] = byte((wsrc[7] >> (0 * 8)))

	wdest[40] = byte((wsrc[6] >> (7 * 8)))
	wdest[41] = byte((wsrc[6] >> (6 * 8)))
	wdest[42] = byte((wsrc[6] >> (5 * 8)))
	wdest[43] = byte((wsrc[6] >> (4 * 8)))
	wdest[44] = byte((wsrc[6] >> (3 * 8)))
	wdest[45] = byte((wsrc[6] >> (2 * 8)))
	wdest[46] = byte((wsrc[6] >> (1 * 8)))
	wdest[47] = byte((wsrc[6] >> (0 * 8)))

	wdest[48] = byte((wsrc[5] >> (7 * 8)))
	wdest[49] = byte((wsrc[5] >> (6 * 8)))
	wdest[50] = byte((wsrc[5] >> (5 * 8)))
	wdest[51] = byte((wsrc[5] >> (4 * 8)))
	wdest[52] = byte((wsrc[5] >> (3 * 8)))
	wdest[53] = byte((wsrc[5] >> (2 * 8)))
	wdest[54] = byte((wsrc[5] >> (1 * 8)))
	wdest[55] = byte((wsrc[5] >> (0 * 8)))

	wdest[56] = byte((wsrc[4] >> (7 * 8)))
	wdest[57] = byte((wsrc[4] >> (6 * 8)))
	wdest[58] = byte((wsrc[4] >> (5 * 8)))
	wdest[59] = byte((wsrc[4] >> (4 * 8)))
	wdest[60] = byte((wsrc[4] >> (3 * 8)))
	wdest[61] = byte((wsrc[4] >> (2 * 8)))
	wdest[62] = byte((wsrc[4] >> (1 * 8)))
	wdest[63] = byte((wsrc[4] >> (0 * 8)))
	return nil
}

func ecdsaSignatureToBytes(data []byte, sig *ECDSASignature) {
	C.secp256k1_ecdsa_signature_serialize_compact(ctx,
		(*C.uchar)(unsafe.Pointer(&data[0])), &sig.s)
}

func ecdsaSignatureToBytesAmd64(data []byte, sig *ECDSASignature) {
	wsrc := (*[8]uint64)(unsafe.Pointer(&sig.s))

	data[0] = byte((wsrc[3] >> (7 * 8)))
	data[1] = byte((wsrc[3] >> (6 * 8)))
	data[2] = byte((wsrc[3] >> (5 * 8)))
	data[3] = byte((wsrc[3] >> (4 * 8)))
	data[4] = byte((wsrc[3] >> (3 * 8)))
	data[5] = byte((wsrc[3] >> (2 * 8)))
	data[6] = byte((wsrc[3] >> (1 * 8)))
	data[7] = byte((wsrc[3] >> (0 * 8)))

	data[8] = byte((wsrc[2] >> (7 * 8)))
	data[9] = byte((wsrc[2] >> (6 * 8)))
	data[10] = byte((wsrc[2] >> (5 * 8)))
	data[11] = byte((wsrc[2] >> (4 * 8)))
	data[12] = byte((wsrc[2] >> (3 * 8)))
	data[13] = byte((wsrc[2] >> (2 * 8)))
	data[14] = byte((wsrc[2] >> (1 * 8)))
	data[15] = byte((wsrc[2] >> (0 * 8)))

	data[16] = byte((wsrc[1] >> (7 * 8)))
	data[17] = byte((wsrc[1] >> (6 * 8)))
	data[18] = byte((wsrc[1] >> (5 * 8)))
	data[19] = byte((wsrc[1] >> (4 * 8)))
	data[20] = byte((wsrc[1] >> (3 * 8)))
	data[21] = byte((wsrc[1] >> (2 * 8)))
	data[22] = byte((wsrc[1] >> (1 * 8)))
	data[23] = byte((wsrc[1] >> (0 * 8)))

	data[24] = byte((wsrc[0] >> (7 * 8)))
	data[25] = byte((wsrc[0] >> (6 * 8)))
	data[26] = byte((wsrc[0] >> (5 * 8)))
	data[27] = byte((wsrc[0] >> (4 * 8)))
	data[28] = byte((wsrc[0] >> (3 * 8)))
	data[29] = byte((wsrc[0] >> (2 * 8)))
	data[30] = byte((wsrc[0] >> (1 * 8)))
	data[31] = byte((wsrc[0] >> (0 * 8)))

	data[32] = byte((wsrc[7] >> (7 * 8)))
	data[33] = byte((wsrc[7] >> (6 * 8)))
	data[34] = byte((wsrc[7] >> (5 * 8)))
	data[35] = byte((wsrc[7] >> (4 * 8)))
	data[36] = byte((wsrc[7] >> (3 * 8)))
	data[37] = byte((wsrc[7] >> (2 * 8)))
	data[38] = byte((wsrc[7] >> (1 * 8)))
	data[39] = byte((wsrc[7] >> (0 * 8)))

	data[40] = byte((wsrc[6] >> (7 * 8)))
	data[41] = byte((wsrc[6] >> (6 * 8)))
	data[42] = byte((wsrc[6] >> (5 * 8)))
	data[43] = byte((wsrc[6] >> (4 * 8)))
	data[44] = byte((wsrc[6] >> (3 * 8)))
	data[45] = byte((wsrc[6] >> (2 * 8)))
	data[46] = byte((wsrc[6] >> (1 * 8)))
	data[47] = byte((wsrc[6] >> (0 * 8)))

	data[48] = byte((wsrc[5] >> (7 * 8)))
	data[49] = byte((wsrc[5] >> (6 * 8)))
	data[50] = byte((wsrc[5] >> (5 * 8)))
	data[51] = byte((wsrc[5] >> (4 * 8)))
	data[52] = byte((wsrc[5] >> (3 * 8)))
	data[53] = byte((wsrc[5] >> (2 * 8)))
	data[54] = byte((wsrc[5] >> (1 * 8)))
	data[55] = byte((wsrc[5] >> (0 * 8)))

	data[56] = byte((wsrc[4] >> (7 * 8)))
	data[57] = byte((wsrc[4] >> (6 * 8)))
	data[58] = byte((wsrc[4] >> (5 * 8)))
	data[59] = byte((wsrc[4] >> (4 * 8)))
	data[60] = byte((wsrc[4] >> (3 * 8)))
	data[61] = byte((wsrc[4] >> (2 * 8)))
	data[62] = byte((wsrc[4] >> (1 * 8)))
	data[63] = byte((wsrc[4] >> (0 * 8)))
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
