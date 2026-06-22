# secp256k1
## secp256k1 in Go

This library uses a pure Go implementation with CGO_ENABLED=0, but uses 
platform specific code when CGO_ENABLED=0 is not set, delivering better
performance.

There are some platform specific optimizations for amd64 and arm64 which can be
disabled by compiling with the tag `forceportable`.

Benchmark against other libraries available
[here](https://github.com/allocz/secpbench).

## Acknowledgments

* [secp256k1](https://github.com/bitcoin-core/secp256k1): C implementation of
secp256k1.
* [dcrec](https://github.com/decred/dcrd/tree/master/dcrec/secp256k1): Pure Go
secp256k1 implementation.
* [btcec](https://github.com/btcsuite/btcd/tree/master/btcec): Schnorr signature
implementation in Go.
