package secp256k1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

type ecdsaVectorErr int

const (
	eveNone ecdsaVectorErr = iota
	evePubKeyParse
	eveInvalidSig
)

var ecdsaTestVector = []struct {
	name   string
	priv   string
	pub    string
	msg    string
	sig    string
	expErr ecdsaVectorErr
}{
	{
		name: "ok",
		priv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		pub:  "046A04AB98D9E4774AD806E302DDDEB63BEA16B5CB5F223EE77478E861BB583EB336B6FBCB60B5B3D4F1551AC45E5FFC4936466E7D98F6C7C0EC736539F74691A6",
		msg:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		sig:  "B81960B4969B423199DEA555F562A66B7F49DEA5836A0168361F1A5F8A3C829803EEA7D7EE4462E3E9D6D59220F950564CAEB77F7B1CDB42AF3C83B013FF3B2F",
	},
	{
		name:   "pub X == P",
		pub:    "0411579208923731619542357098500868790785326998466564056403945758400790883467166336B6FBCB60B5B3D4F1551AC45E5FFC4936466E7D98F6C7C0EC736539F74691A6",
		expErr: evePubKeyParse,
	},
	{
		name:   "pub X > P",
		pub:    "0411579208923731619542357098500868790785326998466564056403945758410790883467166336B6FBCB60B5B3D4F1551AC45E5FFC4936466E7D98F6C7C0EC736539F74691A6",
		expErr: evePubKeyParse,
	},
	{
		name:   "pub Y == P",
		pub:    "046A04AB98D9E4774AD806E302DDDEB63BEA16B5CB5F223EE77478E861BB583EB3115792089237316195423570985008687907853269984665640564039457584007908834671663",
		expErr: evePubKeyParse,
	},
	{
		name:   "pub Y > P",
		pub:    "046A04AB98D9E4774AD806E302DDDEB63BEA16B5CB5F223EE77478E861BB583EB3115792089237316195423570985008687907853269984665640564039457584007908834671664",
		expErr: evePubKeyParse,
	},
	{
		name:   "pub empty",
		pub:    "",
		expErr: evePubKeyParse,
	},
	{
		name:   "pub point not in the curve",
		pub:    "046A04AB98D9E4774AD806E302DDDEB63BEA16B5CB5F223EE77478E861BB583EB336B6FBCB60B5B3D4F1551AC45E5FFC4936466E7D98F6C7C0EC736539F74691A7",
		expErr: evePubKeyParse,
	},
	{
		name:   "invalid signature",
		priv:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		pub:    "046A04AB98D9E4774AD806E302DDDEB63BEA16B5CB5F223EE77478E861BB583EB336B6FBCB60B5B3D4F1551AC45E5FFC4936466E7D98F6C7C0EC736539F74691A6",
		msg:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		sig:    "B81960B4969B423199DEA555F562A66B7F49DEA5836A0168361F1A5F8A3C829803EEA7D7EE4462E3E9D6D59220F950564CAEB77F7B1CDB42AF3C83B013FF3B2E",
		expErr: eveInvalidSig,
	},
}

func testECDSASig(t *testing.T, i int) (ecdsaVectorErr, error) {
	test := ecdsaTestVector[i]
	var (
		privb       [32]byte
		pubb, pub2b [65]byte
		msgb        []byte
		sigb, sig2b [64]byte

		priv      PrivateKey
		pub, pub2 PublicKey
		sig, sig2 ECDSASignature
	)
	privb = htob32(test.priv)
	pubb = htob65(test.pub)
	msgb = htos(test.msg)
	sigb = htob64(test.sig)
	switch test.expErr {

	case eveNone:
		noErr(t, priv.FromBytes32(privb[:]))

		noErr(t, pub.FromBytes64(pubb[1:]))
		noErr(t, pub2.FromPrivateKey(&priv))
		pub2.ToBytes64(pub2b[1:])
		eq(t, pubb[1:], pub2b[1:])

		sig.FromBytes64(sigb[:])
		noErr(t, sig2.Sign(&priv, msgb))
		sig2.ToBytes64(sig2b[:])
		eq(t, sigb, sig2b)

		eq(t, true, sig.Verify(&pub, msgb))

	case evePubKeyParse:
		err := pub.FromBytes64(pubb[1:])
		if err != nil {
			return evePubKeyParse, nil
		}

	case eveInvalidSig:
		noErr(t, pub.FromBytes64(pubb[1:]))
		noErr(t, sig.FromBytes64(sig2b[:]))
		if !sig.Verify(&pub, msgb) {
			return eveInvalidSig, nil
		}
	}

	return eveNone, nil
}

func TestECDSASig(t *testing.T) {
	for i, test := range ecdsaTestVector {
		t.Run(test.name, func(t *testing.T) {
			errCode, err := testECDSASig(t, i)
			noErr(t, err)
			if test.expErr != errCode {
				t.Fatalf("unexpected errCode %d", errCode)
			}
		})
	}
}

type schnorrVectorErrKind int

const (
	sveNone schnorrVectorErrKind = iota
	sveParsePub
	sveInvalidSig
)

var bip340Vector = []struct {
	secKey  [32]byte
	pubKey  [32]byte
	auxRand [32]byte
	msg     []byte
	sig     [64]byte
	pass    bool
	errKind schnorrVectorErrKind
	comment string
}{
	{
		secKey:  htob32("0000000000000000000000000000000000000000000000000000000000000003"),
		pubKey:  htob32("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
		auxRand: htob32("0000000000000000000000000000000000000000000000000000000000000000"),
		msg:     htos("0000000000000000000000000000000000000000000000000000000000000000"),
		sig:     htob64("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
		pass:    true,
		comment: "0",
	},
	{
		secKey:  htob32("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32("0000000000000000000000000000000000000000000000000000000000000001"),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
		pass:    true,
		comment: "1",
	},
	{
		secKey:  htob32("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"),
		pubKey:  htob32("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"),
		auxRand: htob32("C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"),
		msg:     htos("7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
		sig:     htob64("5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
		pass:    true,
		comment: "2",
	},
	{
		secKey:  htob32("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"),
		pubKey:  htob32("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"),
		auxRand: htob32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
		msg:     htos("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
		sig:     htob64("7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"),
		pass:    true,
		comment: "test fails if msg is htos modulo p or n",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"),
		auxRand: htob32(""),
		msg:     htos("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"),
		sig:     htob64("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"),
		pass:    true,
		comment: "4",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
		pass:    false,
		errKind: sveParsePub,
		comment: "public key not on the curve",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2"),
		pass:    false,
		errKind: sveInvalidSig,
		comment: "has_even_y(R) is false",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD"),
		pass:    false,
		errKind: sveInvalidSig,
		comment: "negated message",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"),
		pass:    false,
		errKind: sveInvalidSig,
		comment: "negated s value",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051"),
		pass:    false,
		errKind: sveInvalidSig,
		comment: "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197"),
		pass:    false,
		errKind: sveInvalidSig,
		comment: "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
		pass:    false,
		errKind: sveInvalidSig,
		comment: "sig[0:32] is not an X coordinate on the curve",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
		pass:    false,
		errKind: sveInvalidSig,
		comment: "sig[0:32] is equal to field size",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
		pass:    false,
		errKind: sveInvalidSig,
		comment: "sig[32:64] is equal to curve order",
	},
	{
		secKey:  htob32(""),
		pubKey:  htob32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"),
		auxRand: htob32(""),
		msg:     htos("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
		sig:     htob64("6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"),
		pass:    false,
		errKind: sveParsePub,
		comment: "public key is not a valid X coordinate because it exceeds the field size",
	},
	{
		secKey:  htob32("0340034003400340034003400340034003400340034003400340034003400340"),
		pubKey:  htob32("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"),
		auxRand: htob32("0000000000000000000000000000000000000000000000000000000000000000"),
		msg:     htos(""),
		sig:     htob64("71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63"),
		pass:    true,
		comment: "message of size 0 (added 2022-12)",
	},
	{
		secKey:  htob32("0340034003400340034003400340034003400340034003400340034003400340"),
		pubKey:  htob32("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"),
		auxRand: htob32("0000000000000000000000000000000000000000000000000000000000000000"),
		msg:     htos("11"),
		sig:     htob64("08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF"),
		pass:    true,
		comment: "message of size 1 (added 2022-12)",
	},
	{
		secKey:  htob32("0340034003400340034003400340034003400340034003400340034003400340"),
		pubKey:  htob32("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"),
		auxRand: htob32("0000000000000000000000000000000000000000000000000000000000000000"),
		msg:     htos("0102030405060708090A0B0C0D0E0F1011"),
		sig:     htob64("5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5"),
		pass:    true,
		comment: "message of size 17 (added 2022-12)",
	},
	{
		secKey:  htob32("0340034003400340034003400340034003400340034003400340034003400340"),
		pubKey:  htob32("778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"),
		auxRand: htob32("0000000000000000000000000000000000000000000000000000000000000000"),
		msg:     htos("99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"),
		sig:     htob64("403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367"),
		pass:    true,
		comment: "message of size 100 (added 2022-12)",
	},
}

func TestSchnorrSig(t *testing.T) {
	for i, test := range bip340Vector {
		t.Run(test.comment, func(t *testing.T) {
			eKind, err := schnorrTest(t, i)
			noErr(t, err)
			if eKind != test.errKind {
				t.Fatalf("expecting error kind %d, got %d",
					test.errKind, eKind)
			}
		})
	}
}

func schnorrTest(t *testing.T, i int) (schnorrVectorErrKind, error) {
	var (
		test = bip340Vector[i]
		sve  = sveNone

		priv        PrivateKey
		pub, pub2   PublicKey
		sig, sig2   SchnorrSignature
		sigb, sig2b [64]byte
		pubb, pub2b [65]byte
	)
	switch {
	case !isZeroS(test.secKey[:]) && test.errKind == sveNone:
		eq(t, nil, SchnorrKeyPairFromBytes32(&priv, &pub, test.secKey[:]))
		pub.ToBytes64(pubb[1:])
		eq(t, pubb[1:33], test.pubKey[:])
		noErr(t, pub2.FromBytes32(test.pubKey[:]))
		pub2.ToBytes64(pub2b[:])
		eq(t, pub2b[0:32], test.pubKey[:])
		noErr(t, sig.SignExt(&priv, test.msg, &test.auxRand, false))
		noErr(t, sig2.FromBytes64(test.sig[:]))
		eq(t, sig.ToBytes64(sigb[:]), sig2.ToBytes64(sig2b[:]))
		eq(t, true, sig.Verify(&pub, test.msg))
		return sve, nil

	case test.errKind == sveNone:
		noErr(t, pub.FromBytes32(test.pubKey[:]))
		noErr(t, sig.FromBytes64(test.sig[:]))
		eq(t, true, sig.Verify(&pub, test.msg))
		return sve, nil

	default:
		if pub.FromBytes32(test.pubKey[:]) != nil {
			return sveParsePub, nil
		}
		noErr(t, sig.FromBytes64(test.sig[:]))
		if !sig.Verify(&pub, test.msg) {
			return sveInvalidSig, nil
		}
		return sveNone, fmt.Errorf("expecting failure")
	}
}

func BenchmarkPrivateKeyFromBytes(b *testing.B) {
	var privb [32]byte
	var priv PrivateKey

	for b.Loop() {
		priv.FromBytes32(rov.privb[:])
	}

	if !bytes.Equal(rov.privb[:], priv.ToBytes32(privb[:])) {
		b.Error("serialized private keys do not match")
	}
}

func BenchmarkPrivateKeyToBytes(b *testing.B) {
	var privb [32]byte
	var priv PrivateKey
	priv.FromBytes32(rov.privb[:])

	for b.Loop() {
		priv.ToBytes32(privb[:])
	}

	if !bytes.Equal(rov.privb[:], privb[:]) {
		b.Error("serialized private keys do not match")
	}
}

func BenchmarkPublicKeyFromBytes(b *testing.B) {
	var pubb [65]byte
	var pub PublicKey

	for b.Loop() {
		pub.FromBytes64(rov.pubb[1:])
	}

	if !bytes.Equal(rov.pubb[1:], pub.ToBytes64(pubb[1:])) {
		b.Errorf("serialized public keys do not match")
	}
}

func BenchmarkPublicKeyToBytes(b *testing.B) {
	var pubb [65]byte
	var pub PublicKey
	pub.FromBytes64(rov.pubb[1:])

	for b.Loop() {
		pub.ToBytes64(pubb[1:])
	}

	if !bytes.Equal(rov.pubb[1:], pubb[1:]) {
		b.Errorf("serialized public keys do not match")
	}
}

func BenchmarkPublicKeyFromPrivateKey(b *testing.B) {
	var priv PrivateKey
	var pubb [65]byte
	var pub PublicKey
	priv.FromBytes32(rov.privb[:])

	for b.Loop() {
		pub.FromPrivateKey(&priv)
	}

	if !bytes.Equal(rov.pubb[1:], pub.ToBytes64(pubb[1:])) {
		b.Errorf("serialized public keys do not match")
	}
}

func BenchmarkECDSASignatureFromBytes(b *testing.B) {
	var sigb [64]byte
	var sig ECDSASignature

	for b.Loop() {
		sig.FromBytes64(rov.sigb[:])
	}

	if !bytes.Equal(rov.sigb[:], sig.ToBytes64(sigb[:])) {
		b.Errorf("serialized signatures do not match")
	}
}

func BenchmarkECDSASignatureToBytes(b *testing.B) {
	var sigb [64]byte
	var sig ECDSASignature
	sig.FromBytes64(rov.sigb[:])

	for b.Loop() {
		sig.ToBytes64(sigb[:])
	}

	if !bytes.Equal(rov.sigb[:], sigb[:]) {
		b.Errorf("serialized signatures do not match")
	}
}

func BenchmarkECDSASign(b *testing.B) {
	var sigb [64]byte
	var sig ECDSASignature
	var priv PrivateKey
	priv.FromBytes32(rov.privb[:])

	for b.Loop() {
		sig.Sign(&priv, rov.msghash[:])
	}

	if !bytes.Equal(rov.sigb[:], sig.ToBytes64(sigb[:])) {
		b.Errorf("serialized signatures do not match")
	}
}

func BenchmarkECDSAVerify(b *testing.B) {
	var sig ECDSASignature
	var pub PublicKey
	var ok bool
	sig.FromBytes64(rov.sigb[:])
	pub.FromBytes64(rov.pubb[1:])

	for b.Loop() {
		ok = sig.Verify(&pub, rov.msghash[:])
	}

	if !ok {
		b.Errorf("unexpected invalid sig")
	}
}

func BenchmarkSchnorrKeyPairFromBytes(b *testing.B) {
	var priv PrivateKey
	var pub PublicKey
	var pubb [65]byte

	for b.Loop() {
		err := SchnorrKeyPairFromBytes32(&priv, &pub, rov.privb[:])
		if err != nil {
			b.Fatal(err)
		}
	}

	if !bytes.Equal(rov.pubb[1:], pub.ToBytes64(pubb[1:])) {
		b.Fatalf("pubkeys does not match %x %x", pubb, rov.pubb)
	}
}

func BenchmarkSchnorrPublicKeyFromBytes(b *testing.B) {
	var pub PublicKey
	var pubb [65]byte

	for b.Loop() {
		pub.FromBytes32(rov.pubb[1:])
	}

	if !bytes.Equal(rov.pubb[1:], pub.ToBytes64(pubb[1:])) {
		b.Fatalf("pubkeys does not match %x %x", pubb, rov.pubb)
	}
}

func BenchmarkSchnorrSignatureFromBytes(b *testing.B) {
	var sig SchnorrSignature
	var sigb [64]byte

	for b.Loop() {
		sig.FromBytes64(rov.ssigb[:])
	}

	if !bytes.Equal(rov.ssigb[:], sig.ToBytes64(sigb[:])) {
		b.Fatal("sig does not match")
	}
}

func BenchmarkSchnorrSignatureToBytes(b *testing.B) {
	var sig SchnorrSignature
	var sigb [64]byte
	sig.FromBytes64(rov.ssigb[:])

	for b.Loop() {
		sig.ToBytes64(sigb[:])
	}

	if !bytes.Equal(rov.ssigb[:], sigb[:]) {
		b.Fatal("sig does not match")
	}
}

func BenchmarkSchnorrSign(b *testing.B) {
	var (
		priv PrivateKey
		sig  SchnorrSignature
		sigb [64]byte
	)
	priv.FromBytes32(rov.privb[:])

	for b.Loop() {
		sig.Sign(&priv, rov.msghash[:])
	}

	if !bytes.Equal(rov.ssigb[:], sig.ToBytes64(sigb[:])) {
		b.Fatalf("sig does not match %x %x", rov.ssigb, sigb)
	}
}

func BenchmarkSchnorrVerify(b *testing.B) {
	var (
		pub PublicKey
		sig SchnorrSignature
		ok  bool
	)
	pub.FromBytes64(rov.pubb[1:])
	sig.FromBytes64(rov.ssigb[:])

	for b.Loop() {
		ok = sig.Verify(&pub, rov.msghash[:])
	}

	if !ok {
		b.Fatal("signature verification failed")
	}
}

var rov = initROVars()

type roVars struct {
	privb   [32]byte
	pubb    [65]byte
	sigb    [64]byte
	ssigb   [64]byte
	msghash [32]byte
}

func initROVars() roVars {
	var rov roVars

	htob(rov.privb[:], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	htob(rov.pubb[:], "046A04AB98D9E4774AD806E302DDDEB63BEA16B5CB5F223EE77478E861BB583EB336B6FBCB60B5B3D4F1551AC45E5FFC4936466E7D98F6C7C0EC736539F74691A6")
	htob(rov.msghash[:], "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	htob(rov.sigb[:], "B81960B4969B423199DEA555F562A66B7F49DEA5836A0168361F1A5F8A3C829803EEA7D7EE4462E3E9D6D59220F950564CAEB77F7B1CDB42AF3C83B013FF3B2F")
	htob(rov.ssigb[:], "EDA3C4AA41E0B9A0A20F290FFEADB8E8F855643027CA647C055B150E1D0957DA698B14E0684C3B33431673894DD71BF45BBF315A01B35328467D6AFA3DE186D0")
	return rov
}

func htob32(s string) (dest [32]byte) {
	hex.Decode(dest[:], unsafe.Slice(unsafe.StringData(s), min(len(s), 64)))
	return dest
}

func htos(s string) (dest []byte) {
	dest = make([]byte, len(s)/2)
	hex.Decode(dest, unsafe.Slice(unsafe.StringData(s), len(s)))
	return dest
}

func htob64(s string) (dest [64]byte) {
	hex.Decode(dest[:], unsafe.Slice(unsafe.StringData(s), min(len(s), 128)))
	return dest
}

func htob65(s string) (dest [65]byte) {
	hex.Decode(dest[:], unsafe.Slice(unsafe.StringData(s), min(len(s), 130)))
	return dest
}

func isZeroS(s []byte) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

func htob(dest []byte, s string) {
	b := unsafe.Slice(unsafe.StringData(s), len(s))
	hex.Decode(dest, b)
}

func noErr(t *testing.T, err error) {
	if err == nil {
		return
	}
	_, f, l, _ := runtime.Caller(1)
	t.Fatalf("%s:%d: %v", f, l, err)
}

func notNil[T any](t *testing.T, ptr *T) {
	if ptr != nil {
		return
	}
	_, f, l, _ := runtime.Caller(1)
	t.Fatalf("%s:%d: expecting not nil", f, l)
}

func eq[T any](t *testing.T, a T, b T) {
	s1 := fmt.Sprintf("%+v", a)
	s2 := fmt.Sprintf("%+v", b)
	if s1 == s2 {
		return
	}
	_, f, l, _ := runtime.Caller(1)
	t.Fatalf("%s:%d: %s != %s", f, l, s1, s2)
}
