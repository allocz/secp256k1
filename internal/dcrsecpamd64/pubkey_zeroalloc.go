package secp256k1

// ParsePubKeyZeroAlloc parses a secp256k1 public key encoded according to the
// format specified by ANSI X9.62-1998, which means it is also compatible with
// the SEC (Standards for Efficient Cryptography) specification which is a
// subset of the former.  In other words, it supports the uncompressed,
// compressed, and hybrid formats as follows:
//
// Compressed:
//
//	<format byte = 0x02/0x03><32-byte X coordinate>
//
// Uncompressed:
//
//	<format byte = 0x04><32-byte X coordinate><32-byte Y coordinate>
//
// Hybrid:
//
//	<format byte = 0x05/0x06><32-byte X coordinate><32-byte Y coordinate>
//
// NOTE: The hybrid format makes little sense in practice an therefore this
// package will not produce public keys serialized in this format.  However,
// this function will properly parse them since they exist in the wild.
func ParsePubKeyZeroAlloc(pubOut *PublicKey, serialized []byte) error {
	if err := pubOut.parse(serialized); err != nil {
		return err
	}
	return nil
}

// PutXY puts p.x and p.y values into xOut and yOut.
func (p *PublicKey) PutXY(xOut, yOut *FieldVal64) {
	*xOut, *yOut = p.x, p.y
}

// SetXY sets p.x and p.y to x and y values.
func (p *PublicKey) SetXY(x, y *FieldVal64) {
	p.x, p.y = *x, *y
}
