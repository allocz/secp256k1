package der

import "fmt"

func Encode(data72 []byte, sig64 []byte) []byte {
	var i int

	// DER marker
	data72[i] = 0x30
	i++

	// DER len placeholder
	i++

	// R marker
	data72[i] = 0x02
	i++

	// R len
	rLen := 32
	rHigh := 0
	for _, b := range sig64[:32] {
		if b == 0 {
			rLen--
			continue
		}
		if b&0x80 != 0 {
			rHigh = 1
		}
		break
	}
	data72[i] = byte(rLen + rHigh)
	i++

	// R data
	data72[i] = 0
	i += rHigh
	copy(data72[i:], sig64[32-rLen:32])
	i += rLen

	// S marker
	data72[i] = 0x02
	i++

	// S len
	sLen := 32
	sHigh := 0
	for _, b := range sig64[32:] {
		if b == 0 {
			sLen--
			continue
		}
		if b&0x80 != 0 {
			sHigh = 1
		}
		break
	}
	data72[i] = byte(sLen + sHigh)
	i++

	// S data
	data72[i] = 0
	i += sHigh
	copy(data72[i:], sig64[64-sLen:])
	i += sLen

	// DER len
	// 02 | rlen | rdata | 02 | slen | sdata
	data72[1] = byte(4 + rLen + rHigh + sLen + sHigh)

	return data72[:i]
}

func Decode(sig64 []byte, data []byte, lax bool) error {
	// marker | size | marker | size | data | marker | size | data
	const minLen = 8
	// marker | size | marker | size | data33 | marker | size | data33
	const maxLen = 72
	// marker | size | data | marker | size | data
	const minTupleLen = 6
	// marker | size | data33 | marker | size | data33
	const maxTupleLen = 70
	// 00 | data32
	const maxIntLen = 33

	dataLen := len(data)
	i := 0

	// Data length
	if len(data) < minLen || len(data) > maxLen {
		return fmt.Errorf("bad DER length")
	}

	// DER marker
	if data[i] != 0x30 {
		return fmt.Errorf("bad DER marker")
	}
	i++

	// Tuple length
	if tl := int(data[i]); tl < minTupleLen || tl > maxTupleLen ||
		tl+i+1 != dataLen {

		return fmt.Errorf("bad tuple length")
	}
	i++

	// R marker
	if data[i] != 0x02 {
		return fmt.Errorf("bad R marker")
	}
	i++

	// R length
	rLen := int(data[i])
	if rLen < 1 || rLen > maxIntLen || rLen+i > dataLen {
		return fmt.Errorf("bad R length")
	}
	rStart := i + 1
	i += rLen

	// R data
	if !lax {
		if data[rStart]&0x80 != 0 {
			return fmt.Errorf("negative R")
		}
		if rLen > 1 && data[rStart] == 0 && data[rStart+1]&0x80 == 0 {
			return fmt.Errorf("R not minimal encoded")
		}
	}
	for rLen > 0 && data[rStart] == 0 {
		rStart++
		rLen--
	}
	copy(sig64[32-rLen:32], data[rStart:rStart+rLen])
	i++

	// S marker
	if i+3 > dataLen {
		return fmt.Errorf("overflow")
	}
	if data[i] != 0x02 {
		return fmt.Errorf("bad S marker")
	}
	i++

	// S length
	sLen := int(data[i])
	if sLen < 1 || sLen > maxIntLen || sLen+i > dataLen {
		return fmt.Errorf("bad S length")
	}
	sStart := i + 1
	i += sLen

	// S data
	if !lax {
		if data[sStart]&0x80 != 0 {
			return fmt.Errorf("negative S")
		}
		if sLen > 1 && data[sStart] == 0 && data[sStart+1]&0x80 == 0 {
			return fmt.Errorf("S not minimal encoded")
		}
	}
	for sLen > 0 && data[sStart] == 0 {
		sStart++
		sLen--
	}
	copy(sig64[64-sLen:64], data[sStart:sStart+sLen])
	i++

	// Don't allow trailing bytes
	if i != dataLen {
		return fmt.Errorf("trailing bytes after S")
	}
	return nil
}
