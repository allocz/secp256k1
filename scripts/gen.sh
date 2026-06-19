#!/usr/bin/env bash
####################
set -e
####################
readonly RELDIR="$(dirname ${0})"
readonly HELP_MSG='usage: < help >'
####################
eprintln() {
	! [ -z "${1}" ] || eprintln "eprintln: missing message"
	printf "${1}\n" 1>&2
	exit 1
}

run() {
	gen "secp256k1.go" "!cgo" "gosecp"
	gen "secp256k1_cgo.go" "cgo" "secp"
}

gen() {
	local file=${1}
	local bconstraints=${2}
	local ecpkg=${3}
	cat << EOF > "${file}"
//go:build ${bconstraints}

package secp256k1

// GENERATED FILE, DO NOT EDIT!

import (
	"github.com/allocz/secp256k1/internal/${ecpkg}"
)

type PrivateKey struct {
	p ${ecpkg}.PrivateKey
}

func (p *PrivateKey) FromBytes32(data []byte) error {
	return p.p.FromBytes32(data)
}

// ToBytes32 serializes the private key into the passed 32 byte buffer and
// returns it
func (p *PrivateKey) ToBytes32(data []byte) []byte {
	return p.p.ToBytes32(data)
}

type PublicKey struct {
	p ${ecpkg}.PublicKey
}

// FromBytes32 initializes from even public key.
func (p *PublicKey) FromBytes32(data []byte) error {
	return p.p.FromBytes32(data)
}

// FromBytes33 initializes from compressed public key.
func (p *PublicKey) FromBytes33(data []byte) error {
	return p.p.FromBytes33(data)
}

// FromBytes64 initializes from a full public key, containing X and Y, 32 bytes
// each.
func (p *PublicKey) FromBytes64(data []byte) error {
	return p.p.FromBytes64(data)
}

func (p *PublicKey) FromPrivateKey(priv *PrivateKey) error {
	return p.p.FromPrivateKey(&priv.p)
}

// ToBytes32 writes the X coordinate into the passed buffer and returns it.
func (p *PublicKey) ToBytes32(data []byte) []byte {
	return p.p.ToBytes32(data)
}

// ToBytes32 writes the compressed public key into the passed buffer and returns
// it.
func (p *PublicKey) ToBytes33(data []byte) []byte {
	return p.p.ToBytes33(data)
}

// ToBytes32 writes the X and Y coordinates into the passed buffer and returns
// it.
func (p *PublicKey) ToBytes64(data []byte) []byte {
	return p.p.ToBytes64(data)
}

type ECDSASignature struct {
	s ${ecpkg}.ECDSASignature
}

// FromBytes64 initializes from R and S, 32 bytes each.
func (s *ECDSASignature) FromBytes64(data []byte) error {
	return s.s.FromBytes64(data)
}

// FromBytes64 initializes from DER. If lax is false, strict canonical DER is
// enforced.
func (s *ECDSASignature) FromDER(data []byte, lax bool) error {
	return s.s.FromDER(data, lax)
}

// ToBytes64 writes R and S into the buffer and returns it.
func (s *ECDSASignature) ToBytes64(data []byte) []byte {
	return s.s.ToBytes64(data)
}

// ToBytes64 writes R and S into the buffer and returns it.
func (s *ECDSASignature) ToDER72(data []byte) []byte {
	return s.s.ToDER72(data)
}

func (s *ECDSASignature) Sign(priv *PrivateKey, hash []byte) error {
	return s.s.Sign(&priv.p, hash)
}

func (s *ECDSASignature) Verify(pub *PublicKey, hash []byte) bool {
	return s.s.Verify(&pub.p, hash)
}

// SchnorrKeyPairFromBytes32 initializes priv and pub with a 32 byte private
// key.
//
// The public key Y will always be even.
func SchnorrKeyPairFromBytes32(priv *PrivateKey, pub *PublicKey,
	data []byte) error {

	${ecpkg}.SchnorrKeyPairFromBytes32(&priv.p, &pub.p, data)
	return nil
}

type SchnorrSignature struct {
	s ${ecpkg}.SchnorrSignature
}

// FromBytes64 initializes s with R and S from the data buffer.
func (s *SchnorrSignature) FromBytes64(data []byte) error {
	return s.s.FromBytes64(data)
}

// ToBytes64 writes R and S into the data buffer, returning it.
func (s *SchnorrSignature) ToBytes64(data []byte) []byte {
	return s.s.ToBytes64(data)
}

// SignExt signs msg with priv, using auxRand as additional entropy to generate
// the nonce.
//
// auxRand being nil is the same as passing a pointer to a zeroed 32 byte array.
//
// fastSign tells the procedure to avoid some verifications, which may cause
// speed up depending of the underlying implementation.
func (s *SchnorrSignature) SignExt(priv *PrivateKey, msg []byte,
	auxRand *[32]byte, fastSign bool) error {

	return s.s.SignExt(&priv.p, msg, auxRand, fastSign)
}

func (s *SchnorrSignature) Sign(priv *PrivateKey, msg []byte) error {
	return s.s.Sign(&priv.p, msg)
}

func (s *SchnorrSignature) Verify(pub *PublicKey, msg []byte) bool {
	return s.s.Verify(&pub.p, msg)
}
EOF
}

####################
run
