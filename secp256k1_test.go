package secp256k1

import (
	"bytes"
	"encoding/hex"
	"testing"
	"unsafe"
)

var volatile int

func BenchmarkPrivateKeyFromBytes(b *testing.B) {
	var privb [32]byte
	var priv PrivateKey

	for b.Loop() {
		PrivateKeyFromBytes(&priv, rov.privb[:])
	}

	PrivateKeyToBytes(privb[:], &priv)
	if !bytes.Equal(rov.privb[:], privb[:]) {
		b.Error("serialized private keys do not match")
	}
}

func BenchmarkPrivateKeyToBytes(b *testing.B) {
	var privb [32]byte
	var priv PrivateKey

	PrivateKeyFromBytes(&priv, rov.privb[:])

	for b.Loop() {
		PrivateKeyToBytes(privb[:], &rov.priv)
	}

	if !bytes.Equal(rov.privb[:], privb[:]) {
		b.Error("serialized private keys do not match")
	}
}

var rov = initROVars()

type roVars struct {
	privb [32]byte
	priv  PrivateKey

	pubb [65]byte

	sigb [64]byte

	ssigb [64]byte

	msghash [32]byte
}

func initROVars() roVars {
	var rov roVars

	htob(rov.privb[:], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	htob(rov.pubb[:], "046a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb336b6fbcb60b5b3d4f1551ac45e5ffc4936466e7d98f6c7c0ec736539f74691a6")

	PrivateKeyFromBytes(&rov.priv, rov.privb[:])

	htob(rov.msghash[:], "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

	htob(rov.sigb[:], "B81960B4969B423199DEA555F562A66B7F49DEA5836A0168361F1A5F8A3C829803EEA7D7EE4462E3E9D6D59220F950564CAEB77F7B1CDB42AF3C83B013FF3B2F")

	return rov
}

func htob(dest []byte, s string) {
	b := unsafe.Slice(unsafe.StringData(s), len(s))
	hex.Decode(dest, b)
}
