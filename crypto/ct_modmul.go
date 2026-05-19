package crypto

import (
	"crypto/elliptic"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/secp256k1"
)

// CTScalarMulAddModN returns (a·b + c) mod curve.Params().N in constant
// time on supported curves. The arguments are reduced mod n before the
// computation.
//
// Used by Schnorr proof construction where the response scalar
// `t = c·x + a mod q` has a secret witness `x` — passing `c·x` through
// Go's `math/big.Int.Mul` is documented as non-constant-time and leaks
// bits of `x` via timing.
//
// Curve dispatch:
//   - secp256k1 → secp256k1.ModNScalar (CT word-level field arithmetic
//     in the underlying library).
//   - Ed25519   → edwards25519.ScMulAdd (the same CT primitive RFC 8032
//     stdlib implementations use for the Ed25519 signing equation).
//   - other     → falls back to math/big arithmetic (NOT constant time).
//     Documented; the only curves the library actually uses today are
//     the two above.
func CTScalarMulAddModN(curve elliptic.Curve, a, b, c *big.Int) *big.Int {
	n := curve.Params().N

	if curve == edwards25519.Edwards() {
		var aB, bB, cB, dst [32]byte
		bigIntToLE32(a, n, &aB)
		bigIntToLE32(b, n, &bB)
		bigIntToLE32(c, n, &cB)
		edwards25519.ScMulAdd(&dst, &aB, &bB, &cB)
		return le32ToBigInt(&dst)
	}
	if curve == secp256k1.S256() {
		var aS, bS, cS, dst secp256k1.ModNScalar
		setModNFromBigInt(&aS, a, n)
		setModNFromBigInt(&bS, b, n)
		setModNFromBigInt(&cS, c, n)
		dst.Mul2(&aS, &bS).Add(&cS)
		var be [32]byte
		dst.PutBytes(&be)
		return new(big.Int).SetBytes(be[:])
	}
	// Fallback for unsupported curves — non-CT but mathematically correct.
	aR := new(big.Int).Mod(a, n)
	bR := new(big.Int).Mod(b, n)
	cR := new(big.Int).Mod(c, n)
	out := new(big.Int).Mul(aR, bR)
	out.Add(out, cR)
	out.Mod(out, n)
	return out
}

// bigIntToLE32 writes (x mod n) into dst as 32-byte little-endian,
// suitable for edwards25519's [32]byte scalar conventions. Panics if
// the reduced value exceeds 32 bytes (which on Ed25519 cannot happen
// for n < 2^253).
func bigIntToLE32(x, n *big.Int, dst *[32]byte) {
	r := new(big.Int).Mod(x, n)
	be := r.Bytes()
	if len(be) > 32 {
		panic("crypto: scalar exceeds 32 bytes after reduction")
	}
	// Zero the destination, then place LE bytes: dst[0] = LSB.
	for i := range dst {
		dst[i] = 0
	}
	for i, v := range be {
		dst[len(be)-1-i] = v
	}
}

// le32ToBigInt is the inverse of bigIntToLE32 for [32]byte inputs.
func le32ToBigInt(b *[32]byte) *big.Int {
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[31-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

// setModNFromBigInt loads (x mod n) into the secp256k1.ModNScalar.
// secp256k1's SetByteSlice handles short inputs by left-padding to 32
// bytes; we explicitly reduce first to keep the function well-defined
// for any *big.Int input.
func setModNFromBigInt(s *secp256k1.ModNScalar, x, n *big.Int) {
	r := new(big.Int).Mod(x, n)
	be := r.Bytes()
	// SetByteSlice expects up to 32 bytes; ModNScalar will reduce mod its
	// own group order (which equals secp256k1's n).
	s.SetByteSlice(be)
}
