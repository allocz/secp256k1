package gosecp

import (
	"errors"
	"fmt"

	secp "github.com/allocz/secp256k1/internal/dcrsecp"
	"github.com/allocz/secp256k1/internal/der"
)

var (
	errWrongInputSize = errors.New("wrong input size")
)

type PrivateKey struct {
	k secp.ModNScalar
}

func (p *PrivateKey) FromBytes32(data []byte) error {
	if len(data) < 32 {
		return errWrongInputSize
	}
	p.k.SetByteSlice(data)
	return nil
}

func (p *PrivateKey) ToBytes32(data []byte) []byte {
	if len(data) < 32 {
		data = make([]byte, 32)
	}
	p.k.PutBytesUnchecked(data)
	return data
}

type PublicKey struct {
	p secp.JacobianPoint
}

func (p *PublicKey) FromBytes32(data []byte) error {
	if len(data) < 32 {
		return errWrongInputSize
	}
	overflow := p.p.X.SetByteSlice(data[0:32])
	if overflow {
		return fmt.Errorf("field value overflow")
	}
	ok := secp.DecompressY(&p.p.X, false, &p.p.Y)
	if !ok {
		return fmt.Errorf("failed to decompress Y")
	}
	p.p.Z.SetInt(1)
	return nil
}

func (p *PublicKey) FromBytes33(data []byte) error {
	if len(data) < 33 {
		return errWrongInputSize
	}
	overflow := p.p.X.SetByteSlice(data[1:33])
	if overflow {
		return fmt.Errorf("field value overflow")
	}
	ok := secp.DecompressY(&p.p.X, data[0] == 0x03, &p.p.Y)
	if !ok {
		return fmt.Errorf("failed to decompress Y")
	}
	p.p.Z.SetInt(1)
	return nil
}

func (p *PublicKey) FromBytes64(data []byte) error {
	if len(data) < 64 {
		return errWrongInputSize
	}
	overflow := p.p.X.SetByteSlice(data[:32])
	if overflow {
		return fmt.Errorf("field value overflow")
	}
	overflow = p.p.Y.SetByteSlice(data[32:64])
	if overflow {
		return fmt.Errorf("field value overflow")
	}
	p.p.Z.SetInt(1)
	if !isOnCurve(&p.p.X, &p.p.Y) {
		return fmt.Errorf("point not in the curve")
	}
	return nil
}

func (p *PublicKey) ToBytes32(data []byte) []byte {
	if len(data) < 32 {
		data = make([]byte, 32)
	}
	p.p.X.PutBytesUnchecked(data)
	if p.p.Y.IsOdd() {
		return nil
	}
	return data
}

func (p *PublicKey) ToBytes33(data []byte) []byte {
	if len(data) < 33 {
		data = make([]byte, 33)
	}
	data[0] = 0x02
	p.p.X.PutBytesUnchecked(data[1:])
	if p.p.Y.IsOdd() {
		data[0] = 0x03
	}
	return data
}

func (p *PublicKey) ToBytes64(data []byte) []byte {
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	p.p.X.PutBytesUnchecked(data)
	p.p.Y.PutBytesUnchecked(data[32:])
	return data
}

func (p *PublicKey) FromPrivateKey(priv *PrivateKey) error {
	secp.ScalarBaseMultNonConst(&priv.k, &p.p)
	p.p.ToAffine()
	return nil
}

type ECDSASignature struct {
	r, s secp.ModNScalar
}

func (e *ECDSASignature) FromBytes64(data []byte) error {
	if len(data) < 64 {
		return errWrongInputSize
	}
	e.r.SetByteSlice(data[:32])
	e.s.SetByteSlice(data[32:])
	return nil
}

func (e *ECDSASignature) FromDER(data []byte, lax bool) error {
	var sig64 [64]byte
	err := der.Decode(sig64[:], data, lax)
	if err != nil {
		return err
	}
	return e.FromBytes64(sig64[:])
}

func (e *ECDSASignature) ToBytes64(data []byte) []byte {
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	e.r.PutBytesUnchecked(data)
	e.s.PutBytesUnchecked(data[32:])
	return data
}

func (e *ECDSASignature) ToDER72(data []byte) []byte {
	if len(data) < 72 {
		data = make([]byte, 72)
	}
	var sig64 [64]byte
	e.ToBytes64(sig64[:])
	return der.Encode(data, sig64[:])
}

func (e *ECDSASignature) Sign(priv *PrivateKey, hash []byte) error {
	if len(hash) != 32 {
		return errWrongInputSize
	}
	ecdsaSign(e, priv, hash)
	return nil
}

func (e *ECDSASignature) Verify(pub *PublicKey, hash []byte) bool {
	if len(hash) != 32 {
		return false
	}
	return ecdsaVerify(e, pub, hash)
}

type SchnorrSignature struct {
	r secp.FieldVal
	s secp.ModNScalar
}

func SchnorrKeyPairFromBytes32(priv *PrivateKey, pub *PublicKey,
	privb []byte) error {

	if len(privb) < 32 {
		return errWrongInputSize
	}
	schnorrKeyPairFromBytes(priv, pub, privb)
	return nil
}

func (s *SchnorrSignature) FromBytes64(data []byte) error {
	if len(data) < 64 {
		return errWrongInputSize
	}
	s.r.SetByteSlice(data[:32])
	s.s.SetByteSlice(data[32:64])
	return nil
}

func (s *SchnorrSignature) ToBytes64(data []byte) []byte {
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	s.r.PutBytesUnchecked(data[:32])
	s.s.PutBytesUnchecked(data[32:])
	return data
}

func (s *SchnorrSignature) SignExt(priv *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) error {

	err := schnorrSignExt(s, priv, msg, auxRand, fastSign)
	if err != nil {
		return err
	}
	return nil
}

func (s *SchnorrSignature) Sign(priv *PrivateKey, msg []byte) error {

	return s.SignExt(priv, msg, nil, false)
}

func (s *SchnorrSignature) Verify(pub *PublicKey, msg []byte) bool {
	return schnorrVerify(s, pub, msg)
}
