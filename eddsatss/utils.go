package eddsatss

import (
	"crypto/elliptic"
	"io"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/common"
)

func encodedBytesToBigInt(s *[32]byte) *big.Int {
	// Use a copy so we don't screw up our original memory.
	sCopy := new([32]byte)
	for i := 0; i < 32; i++ {
		sCopy[i] = s[i]
	}
	reverse(sCopy)
	return new(big.Int).SetBytes(sCopy[:])
}

func bigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}
	// Caveat: a can be longer than 32 bytes.
	s = copyBytes(a.Bytes())
	// Reverse the byte string --> little endian after encoding.
	reverse(s)
	return s
}

// copyBytes copies a big-endian byte slice into a fixed-width 32-byte
// buffer, left-padding with zeros if the input is shorter than 32 bytes
// and taking the low 32 bytes (mathematically: mod 2^256) if longer.
//
// The previous implementation silently took the HIGH 32 bytes for inputs
// longer than 32 bytes, which is the wrong end of a big-endian
// representation — it discarded the low bits, which for an attacker-
// controlled `*big.Int` produced by `new(big.Int).SetBytes(msg.Si)` (a
// peer's wire-format reply) meant a malicious peer could swap which
// bytes of their declared Si end up in the computation. In honest
// callers nothing exceeds 32 bytes (Ed25519 scalars are < 2^253), so
// the new mod-2^256 behaviour leaves the honest path unchanged.
func copyBytes(aB []byte) *[32]byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)
	aBLen := len(aB)
	if aBLen > 32 {
		// Take the LOW 32 bytes (i.e., mod 2^256). For a big-endian
		// input, that's the trailing 32 bytes, NOT the leading ones.
		aB = aB[aBLen-32:]
		aBLen = 32
	}
	// Left-pad short inputs with zero bytes so the value is right-aligned
	// in the output buffer.
	pad := 32 - aBLen
	for i := 0; i < aBLen; i++ {
		s[pad+i] = aB[i]
	}
	return s
}

func ecPointToEncodedBytes(x *big.Int, y *big.Int) *[32]byte {
	s := bigIntToEncodedBytes(y)
	xB := bigIntToEncodedBytes(x)
	xFE := new(edwards25519.FieldElement)
	edwards25519.FeFromBytes(xFE, xB)
	isNegative := edwards25519.FeIsNegative(xFE) == 1

	if isNegative {
		s[31] |= (1 << 7)
	} else {
		s[31] &^= (1 << 7)
	}

	return s
}

func reverse(s *[32]byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func addExtendedElements(p, q edwards25519.ExtendedGroupElement) edwards25519.ExtendedGroupElement {
	var r edwards25519.CompletedGroupElement
	var qCached edwards25519.CachedGroupElement
	q.ToCached(&qCached)
	edwards25519.GeAdd(&r, &p, &qCached)
	var result edwards25519.ExtendedGroupElement
	r.ToExtended(&result)
	return result
}

func ecPointToExtendedElement(ec elliptic.Curve, x *big.Int, y *big.Int, rand io.Reader) edwards25519.ExtendedGroupElement {
	encodedXBytes := bigIntToEncodedBytes(x)
	encodedYBytes := bigIntToEncodedBytes(y)

	z := common.GetRandomPositiveInt(rand, ec.Params().N)
	encodedZBytes := bigIntToEncodedBytes(z)

	var fx, fy, fxy edwards25519.FieldElement
	edwards25519.FeFromBytes(&fx, encodedXBytes)
	edwards25519.FeFromBytes(&fy, encodedYBytes)

	var X, Y, Z, T edwards25519.FieldElement
	edwards25519.FeFromBytes(&Z, encodedZBytes)

	edwards25519.FeMul(&X, &fx, &Z)
	edwards25519.FeMul(&Y, &fy, &Z)
	edwards25519.FeMul(&fxy, &fx, &fy)
	edwards25519.FeMul(&T, &fxy, &Z)

	return edwards25519.ExtendedGroupElement{
		X: X,
		Y: Y,
		Z: Z,
		T: T,
	}
}
