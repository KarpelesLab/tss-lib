package crypto

import (
	"crypto/elliptic"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
)

// CTScalarBaseMultEd25519 computes k·G on Ed25519 in constant time using
// edwards25519.GeScalarMultBase and returns the result as a *ECPoint.
//
// Secret-input version: k is intended for use with per-party EdDSA
// signing nonces (ri, di, ei) or other secret scalars. The standard
// ScalarBaseMult routes through Go's elliptic curve implementation,
// which is documented as NOT constant-time for these curves —
// observing it on shared hardware is a known channel for nonce-bias
// attacks against EdDSA / FROST signatures. GeScalarMultBase uses a
// fixed-base table with CT lookup, closing the channel.
//
// If `ec` is not the Ed25519 curve, the function falls back to the
// non-CT primitive so callers using a different curve continue to
// receive a correct (if non-CT) result.
func CTScalarBaseMultEd25519(ec elliptic.Curve, k *big.Int) *ECPoint {
	if ec != edwards25519.Edwards() {
		return ScalarBaseMult(ec, k)
	}
	red := new(big.Int).Mod(k, ec.Params().N)

	// Encode reduced scalar as 32-byte little-endian, padding leading
	// zeros if the big-endian representation is shorter.
	be := red.Bytes()
	if len(be) > 32 {
		be = be[len(be)-32:]
	}
	var sBytes [32]byte
	pad := 32 - len(be)
	for i, v := range be {
		sBytes[31-(i+pad)] = v
	}

	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &sBytes)

	// Convert extended (X, Y, Z, T) to affine (X/Z, Y/Z).
	var zInv, xFE, yFE edwards25519.FieldElement
	edwards25519.FeInvert(&zInv, &R.Z)
	edwards25519.FeMul(&xFE, &R.X, &zInv)
	edwards25519.FeMul(&yFE, &R.Y, &zInv)
	var xBytes, yBytes [32]byte
	edwards25519.FeToBytes(&xBytes, &xFE)
	edwards25519.FeToBytes(&yBytes, &yFE)

	beX := make([]byte, 32)
	beY := make([]byte, 32)
	for i := 0; i < 32; i++ {
		beX[31-i] = xBytes[i]
		beY[31-i] = yBytes[i]
	}
	return NewECPointNoCurveCheck(ec, new(big.Int).SetBytes(beX), new(big.Int).SetBytes(beY))
}
