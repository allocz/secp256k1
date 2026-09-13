package secp256k1

import (
	"crypto/sha256"
	"sync"
)

func (h *hmacsha256) Sum2(outBuf, tmpBuf []byte) []byte {
       h.outer.Reset()
       h.outer.Write(h.opad[:])
       h.outer.Write(h.inner.Sum(tmpBuf))
       outBuf = h.outer.Sum(outBuf)
       return outBuf
}

type hmacPool struct {
       p sync.Pool
}

func (h *hmacPool) Get(key []byte) *hmacsha256 {
       hs := h.p.Get().(*hmacsha256)
       hs.initKey(key)
       return hs
}

func (h *hmacPool) Put(hs *hmacsha256) {
       hs.inner.Reset()
       hs.outer.Reset()
       *hs = hmacsha256{
               inner: hs.inner,
               outer: hs.outer,
       }
       h.p.Put(hs)
}

var hmacP = hmacPool{
       p: sync.Pool{
               New: func() any {
                       h := new(hmacsha256)
                       h.inner = sha256.New()
                       h.outer = sha256.New()
                       return h
               },
       },
}

const (
       // keyBufSize is the size of privKeyLen + hashLen + extraLen +
       // versionLen
       keyBufSize       = 32 + 32 + 32 + 16
       bufPoolMinBufCap = keyBufSize
       bufPoolSize      = 4
)

type bufPool struct {
       p sync.Pool
}

func (b *bufPool) Get() *[bufPoolSize][bufPoolMinBufCap]byte {
       return b.p.Get().(*[bufPoolSize][bufPoolMinBufCap]byte)
}

func (b *bufPool) Put(bufs *[bufPoolSize][bufPoolMinBufCap]byte) {
       clear(bufs[:])
       b.p.Put(bufs)
}

var bufP = bufPool{
       p: sync.Pool{
               New: func() any {
                       return &[bufPoolSize][bufPoolMinBufCap]byte{}
               },
       },
}

// NonceRFC6979ZeroAlloc generates a nonce deterministically according to
// RFC 6979 using HMAC-SHA256 for the hashing function.  It takes a 32-byte hash
// as an input and returns a 32-byte nonce to be used for deterministic signing.
// The extra and version arguments are optional, but allow additional data to be
// added to the input of the HMAC.  When provided, the extra data must be
// 32-bytes and version must be 16 bytes or they will be ignored.
//
// Finally, the extraIterations parameter provides a method to produce a stream
// of deterministic nonces to ensure the signing code is able to produce a nonce
// that results in a valid signature in the extremely unlikely event the
// original nonce produced results in an invalid signature (e.g. R == 0).
// Signing code should start with 0 and increment it if necessary.
func NonceRFC6979ZeroAlloc(nonceOut *ModNScalar, privKey []byte, hash []byte,
	extra []byte, version []byte, extraIterations uint32) {

	// Input to HMAC is the 32-byte private key and the 32-byte hash.  In
	// addition, it may include the optional 32-byte extra data and 16-byte
	// version.  Create a fixed-size array to avoid extra allocs and slice
	// it properly.
	const (
		privKeyLen = 32
		hashLen    = 32
		extraLen   = 32
		versionLen = 16
	)
	var keyBuf, k, v, tmp []byte
	{
	        bufs := bufP.Get()
	        defer bufP.Put(bufs)
	        keyBuf, k, v, tmp = bufs[0][:], bufs[1][:], bufs[2][:],
	                bufs[3][:]
	}
	keyBuf = keyBuf[:privKeyLen+hashLen+extraLen+versionLen]

	// Truncate rightmost bytes of private key and hash if they are too long
	// and leave left padding of zeros when they're too short.
	if len(privKey) > privKeyLen {
		privKey = privKey[:privKeyLen]
	}
	if len(hash) > hashLen {
		hash = hash[:hashLen]
	}
	offset := privKeyLen - len(privKey) // Zero left padding if needed.
	offset += copy(keyBuf[offset:], privKey)
	offset += hashLen - len(hash) // Zero left padding if needed.
	offset += copy(keyBuf[offset:], hash)
	if len(extra) == extraLen {
		offset += copy(keyBuf[offset:], extra)
		if len(version) == versionLen {
			offset += copy(keyBuf[offset:], version)
		}
	} else if len(version) == versionLen {
		// When the version was specified, but not the extra data, leave
		// the extra data portion all zero.
		offset += privKeyLen
		offset += copy(keyBuf[offset:], version)
	}
	key := keyBuf[:offset]

	// Step B.
	//
	// V = 0x01 0x01 0x01 ... 0x01 such that the length of V, in bits, is
	// equal to 8*ceil(hashLen/8).
	//
	// Note that since the hash length is a multiple of 8 for the chosen
	// hash function in this optimized implementation, the result is just
	// the hash length, so avoid the extra calculations.  Also, since it
	// isn't modified, start with a global value.
	v = v[:len(oneInitializer)]
	copy(v, oneInitializer)

	// Step C (Go zeroes all allocated memory).
	//
	// K = 0x00 0x00 0x00 ... 0x00 such that the length of K, in bits, is
	// equal to 8*ceil(hashLen/8).
	//
	// As above, since the hash length is a multiple of 8 for the chosen
	// hash function in this optimized implementation, the result is just
	// the hash length, so avoid the extra calculations.
	k = k[:hashLen]
	copy(k, zeroInitializer[:hashLen])

	// Step D.
	//
	// K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
	//
	// Note that key is the "int2octets(x) || bits2octets(h1)" portion along
	// with potential additional data as described by section 3.6 of the
	// RFC.
	hasher := hmacP.Get(k)
	defer hmacP.Put(hasher)
	hasher.Write(oneInitializer)
	hasher.Write(singleZero)
	hasher.Write(key)
	k = hasher.Sum2(k[:0], tmp[:0])

	// Step E.
	//
	// V = HMAC_K(V)
	hasher.ResetKey(k)
	hasher.Write(v)
	v = hasher.Sum2(v[:0], tmp[:0])

	// Step F.
	//
	// K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
	//
	// Note that key is the "int2octets(x) || bits2octets(h1)" portion along
	// with potential additional data as described by section 3.6 of the
	// RFC.
	hasher.Reset()
	hasher.Write(v)
	hasher.Write(singleOne)
	hasher.Write(key)
	k = hasher.Sum2(k[:0], tmp[:0])

	// Step G.
	//
	// V = HMAC_K(V)
	hasher.ResetKey(k)
	hasher.Write(v)
	v = hasher.Sum2(v[:0], tmp[:0])

	// Step H.
	//
	// Repeat until the value is nonzero and less than the curve order.
	var generated uint32
	for {
		// Step H1 and H2.
		//
		// Set T to the empty sequence.  The length of T (in bits) is
		// denoted tlen; thus, at that point, tlen = 0.
		//
		// While tlen < qlen, do the following:
		//   V = HMAC_K(V)
		//   T = T || V
		//
		// Note that because the hash function output is the same length
		// as the private key in this optimized implementation, there is
		// no need to loop or create an intermediate T.
		hasher.Reset()
		hasher.Write(v)
		v = hasher.Sum2(v[:0], tmp[:0])

		// Step H3.
		//
		// k = bits2int(T)
		// If k is within the range [1,q-1], return it.
		//
		// Otherwise, compute:
		// K = HMAC_K(V || 0x00)
		// V = HMAC_K(V)
		overflow := nonceOut.SetByteSlice(v)
		if !overflow && !nonceOut.IsZero() {
			generated++
			if generated > extraIterations {
				return
			}
		}

		// K = HMAC_K(V || 0x00)
		hasher.Reset()
		hasher.Write(v)
		hasher.Write(singleZero)
		k = hasher.Sum2(k[:0], tmp[:0])

		// V = HMAC_K(V)
		hasher.ResetKey(k)
		hasher.Write(v)
		v = hasher.Sum2(v[:0], tmp[:0])
	}
}
