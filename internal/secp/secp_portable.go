//go:build cgo && (!amd64 || forceportable)

package secp

func (p *PublicKey) ToBytes32(data []byte) []byte {
	return p.toBytes32(data)
}

func (p *PublicKey) ToBytes33(data []byte) []byte {
	return p.toBytes33(data)
}

func (p *PublicKey) ToBytes64(data []byte) []byte {
	return p.toBytes64(data)
}

func (e *ECDSASignature) FromBytes64(data []byte) *ECDSASignature {
	return e.fromBytes64(data)
}

func (e *ECDSASignature) ToBytes64(data []byte) []byte {
	return e.toBytes64(data)
}
