//go:build cgo && amd64 && !forceportable

package secp

import "unsafe"

func (p *PublicKey) ToBytes32(data []byte) []byte {
	if p == nil {
		return nil
	}
	if len(data) < 32 {
		data = make([]byte, 32)
	}

	wsrc := (*[8]uint64)(unsafe.Pointer(&p.p.P))

	if wsrc[4]&0x1 != 0 {
		return nil
	}

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

	return data
}

func (p *PublicKey) ToBytes33(data []byte) []byte {
	if p == nil {
		return nil
	}
	if len(data) < 33 {
		data = make([]byte, 33)
	}
	wsrc := (*[8]uint64)(unsafe.Pointer(&p.p.P))

	data[0] = 0x02
	if wsrc[4]&0x1 != 0 {
		data[0] = 0x03
	}

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

	return data
}

func (p *PublicKey) ToBytes64(data []byte) []byte {
	if p == nil {
		return nil
	}
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	wsrc := (*[8]uint64)(unsafe.Pointer(&p.p.P))

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

	return data
}

func (e *ECDSASignature) FromBytes64(data []byte) error {
	if e == nil {
		return nil
	}
	if len(data) < 64 {
		return errWrongInputSize
	}
	wsrc := (*[8]uint64)(unsafe.Pointer(&data[0]))
	wdest := (*[64]byte)(unsafe.Pointer(&e.e.S))

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

func (e *ECDSASignature) ToBytes64(data []byte) []byte {
	if e == nil {
		return nil
	}
	if len(data) < 64 {
		data = make([]byte, 64)
	}
	wsrc := (*[8]uint64)(unsafe.Pointer(&e.e.S))

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

	return data
}
