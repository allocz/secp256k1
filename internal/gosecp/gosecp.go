package gosecp

import (
	secp "github.com/allocz/secp256k1/internal/dcrsecp"
)

type PrivateKey struct {
	k secp.ModNScalar
}

func (p *PrivateKey) FromBytes32(data []byte) *PrivateKey {
	if p == nil {
		return nil
	}
	if len(data) < 32 {
		return nil
	}
	p.k.SetByteSlice(data)
	return p
}

func (p *PrivateKey) ToBytes32(data []byte) []byte {
	if p == nil {
		return nil
	}
	if len(data) < 32 {
		data = make([]byte, 32)
	}
	p.k.PutBytesUnchecked(data)
	return data
}

type PublicKey struct {
	p secp.JacobianPoint
}

func (p *PublicKey) FromBytes32(data []byte) *PublicKey {
	if p == nil {
		return nil
	}
	if len(data) < 32 {
		return nil
	}
	overflow := p.p.X.SetByteSlice(data[0:32])
	if overflow {
		return nil
	}
	ok := secp.DecompressY(&p.p.X, false, &p.p.Y)
	if !ok {
		return nil
	}
	p.p.Z.SetInt(1)
	return p
}

func (p *PublicKey) FromBytes33(data []byte) *PublicKey {
	if p == nil {
		return nil
	}
	if len(data) < 33 {
		return nil
	}
	overflow := p.p.X.SetByteSlice(data[1:33])
	if overflow {
		return nil
	}
	ok := secp.DecompressY(&p.p.X, data[0] == 0x03, &p.p.Y)
	if !ok {
		return nil
	}
	p.p.Z.SetInt(1)
	return p
}

func (p *PublicKey) FromBytes64(data []byte) *PublicKey {
	if p == nil {
		return nil
	}
	if len(data) < 64 {
		return nil
	}
	p.p.X.SetByteSlice(data[:32])
	p.p.Y.SetByteSlice(data[32:64])
	p.p.Z.SetInt(1)
	if !isOnCurve(&p.p.X, &p.p.Y) {
		return nil
	}
	return p
}

func (p *PublicKey) ToBytes32(data []byte) []byte {
	if p == nil {
		return nil
	}
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
	if p == nil {
		return nil
	}
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
	if p == nil {
		return nil
	}
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	p.p.X.PutBytesUnchecked(data)
	p.p.Y.PutBytesUnchecked(data[32:])
	return data
}

func (p *PublicKey) FromPrivateKey(priv *PrivateKey) *PublicKey {
	if p == nil {
		return nil
	}
	if priv == nil {
		return nil
	}
	secp.ScalarBaseMultNonConst(&priv.k, &p.p)
	p.p.ToAffine()
	return p
}

type ECDSASignature struct {
	r, s secp.ModNScalar
}

func (e *ECDSASignature) FromBytes64(data []byte) *ECDSASignature {
	if e == nil {
		return nil
	}
	if len(data) < 64 {
		return nil
	}
	e.r.SetByteSlice(data[:32])
	e.s.SetByteSlice(data[32:])
	return e
}

func (e *ECDSASignature) ToBytes64(data []byte) []byte {
	if e == nil {
		return nil
	}
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	e.r.PutBytesUnchecked(data)
	e.s.PutBytesUnchecked(data[32:])
	return data
}

func (e *ECDSASignature) Sign(priv *PrivateKey, hash []byte) *ECDSASignature {
	if e == nil {
		return nil
	}
	if priv == nil {
		return nil
	}
	if len(hash) != 32 {
		return nil
	}
	ecdsaSign(e, priv, hash)
	return e
}

func (e *ECDSASignature) Verify(pub *PublicKey, hash []byte) bool {
	if e == nil {
		return false
	}
	if pub == nil {
		return nil
	}
	if len(hash) != 32 {
		return nil
	}
	return ecdsaVerify(e, pub, hash)
}

type SchnorrSignature struct {
	r secp.FieldVal
	s secp.ModNScalar
}

func SchnorrKeyPairFromBytes32(priv *PrivateKey, pub *PublicKey,
	privb []byte) error {

	if priv == nil || pub == nil || len(privb) < 32 {
		return
	}
	schnorrKeyPairFromBytes(priv, pub, privb)
	return nil
}

func (s *SchnorrSignature) FromBytes64(data []byte) *SchnorrSignature {
	if s == nil {
		return nil
	}
	if len(data) < 64 {
		return nil
	}
	s.r.SetByteSlice(data[:32])
	s.s.SetByteSlice(data[32:64])
	return s
}

func (s *SchnorrSignature) ToBytes64(data []byte) []byte {
	if s == nil {
		return nil
	}
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	s.r.PutBytesUnchecked(data[:32])
	s.s.PutBytesUnchecked(data[32:])
	return data
}

func (s *SchnorrSignature) SignExt(priv *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) *SchnorrSignature {

	if s == nil {
		return nil
	}
	if priv == nil {
		return nil
	}
	err := schnorrSignExt(s, priv, msg, auxRand, fastSign)
	if err != nil {
		return nil
	}
	return s
}

func (s *SchnorrSignature) Sign(priv *PrivateKey,
	msg []byte) *SchnorrSignature {

	if s == nil {
		return nil
	}
	if priv == nil {
		return nil
	}
	return s.SignExt(priv, msg, nil, false)
}

func (s *SchnorrSignature) Verify(pub *PublicKey, msg []byte) bool {
	if s == nil {
		return false
	}
	if pub == nil {
		return false
	}
	return schnorrVerify(s, pub, msg)
}
