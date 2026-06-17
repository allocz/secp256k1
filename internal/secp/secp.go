//go:build cgo

package secp

import (
	"errors"
	"fmt"

	"github.com/allocz/secp256k1/internal/secp/binding"
	"github.com/allocz/secp256k1/internal/der"
)

var (
	errWrongInputSize = errors.New("wrong input size")
)

type PrivateKey struct {
	k binding.PrivateKey
}

func (p *PrivateKey) FromBytes32(data []byte) error {
	if len(data) < 32 {
		return errWrongInputSize
	}
	copy(p.k.K[0:], data)
	return nil
}

func (p *PrivateKey) ToBytes32(data []byte) []byte {
	if len(data) < 32 {
		data = make([]byte, 32)
	}
	copy(data[0:], p.k.K[:])
	return data
}

type PublicKey struct {
	p binding.PublicKey
}

func (p *PublicKey) FromBytes32(data []byte) error {
	if len(data) < 32 {
		return errWrongInputSize
	}
	var pubb [33]byte
	pubb[0] = 0x02
	copy(pubb[1:], data)
	err := binding.PublicKeyParse33(&p.p, pubb[:])
	if err != nil {
		return err
	}
	return nil
}

func (p *PublicKey) FromBytes33(data []byte) error {
	if len(data) < 33 {
		return errWrongInputSize
	}
	err := binding.PublicKeyParse33(&p.p, data)
	if err != nil {
		return err
	}
	return nil
}

func (p *PublicKey) FromBytes64(data []byte) error {
	if len(data) < 64 {
		return errWrongInputSize
	}
	var pubb [65]byte
	pubb[0] = 0x04
	copy(pubb[1:], data)
	err := binding.PublicKeyParse65(&p.p, pubb[:])
	if err != nil {
		return err
	}
	return nil
}

func (p *PublicKey) toBytes32(data []byte) []byte {
	if len(data) < 32 {
		data = make([]byte, 32)
	}
	var pubb [33]byte
	binding.PublicKeySerialize33(pubb[:], &p.p)
	copy(data, pubb[1:])
	return data
}

func (p *PublicKey) toBytes33(data []byte) []byte {
	if len(data) < 33 {
		data = make([]byte, 33)
	}
	binding.PublicKeySerialize33(data, &p.p)
	return data
}

func (p *PublicKey) toBytes64(data []byte) []byte {
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	var pubb [65]byte
	binding.PublicKeySerialize65(pubb[:], &p.p)
	copy(data, pubb[1:])
	return data
}

func (p *PublicKey) FromPrivateKey(priv *PrivateKey) error {
	err := binding.PublicKeyCreate(&p.p, &priv.k)
	if err != nil {
		return err
	}
	return nil
}

type ECDSASignature struct {
	e binding.ECDSASignature
}

func (e *ECDSASignature) fromBytes64(data []byte) error {
	if len(data) < 64 {
		return errWrongInputSize
	}
	err := binding.ECDSASignatureParseCompact(&e.e, data)
	if err != nil {
		return err
	}
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

func (e *ECDSASignature) toBytes64(data []byte) []byte {
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	binding.ECDSASignatureSerializeCompact(data, &e.e)
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
	err := binding.ECDSASign(&e.e, hash, &priv.k)
	if err != nil {
		return err
	}
	return nil
}

func (e *ECDSASignature) Verify(pub *PublicKey, hash []byte) bool {
	if len(hash) != 32 {
		return false
	}
	return binding.ECDSAVerify(&e.e, hash, &pub.p)
}

type SchnorrSignature struct {
	s binding.SchnorrSignature
}

func SchnorrKeyPairFromBytes32(priv *PrivateKey, pub *PublicKey,
	privb []byte) error {

	if len(privb) < 32 {
		return errWrongInputSize
	}
	err := priv.FromBytes32(privb)
	if err != nil {
		return err
	}
	var pubb [64]byte
	err = pub.FromPrivateKey(priv)
	if err != nil {
		return err
	}
	if pub.ToBytes64(pubb[:]) == nil {
		return fmt.Errorf("error deriving public key")
	}
	if pubb[63]&0x1 != 0 {
		priv := *priv
		defer func() {
			priv = PrivateKey{}
		}()
		binding.PrivateNegate(&priv.k)
		err := pub.FromPrivateKey(&priv)
		if err != nil {
			return err
		}
		if pub.ToBytes64(pubb[:]) == nil {
			return fmt.Errorf("fail derive pub from priv")
		}
	}
	return nil
}

func (s *SchnorrSignature) FromBytes64(data []byte) error {
	if len(data) < 64 {
		return errWrongInputSize
	}
	copy(s.s.S[:], data)
	return nil
}

func (s *SchnorrSignature) ToBytes64(data []byte) []byte {
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	copy(data, s.s.S[:])
	return data
}

func (s *SchnorrSignature) SignExt(priv *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) error {

	err := binding.SchnorrSign(&s.s, msg, &priv.k, auxRand)
	if err != nil {
		return err
	}
	return nil
}

func (s *SchnorrSignature) Sign(priv *PrivateKey,
	msg []byte) error {

	return s.SignExt(priv, msg, nil, false)
}

func (s *SchnorrSignature) Verify(pub *PublicKey, msg []byte) bool {
	return binding.SchnorrVerify(&s.s, &pub.p, msg)
}
