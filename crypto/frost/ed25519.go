package frost

import (
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// ContextString is the FROST(Ed25519, SHA-512) ciphersuite domain separator
// per RFC 9591 §6.1.4. It is mixed into all FROST-specific hashes (H1, H3, H4,
// H5) but deliberately NOT into H2 — H2 is the plain Ed25519 challenge hash so
// FROST(Ed25519) signatures verify under any Ed25519 verifier.
var ContextString = []byte("FROST-ED25519-SHA512-v1")

// L is the Ed25519 group order (subgroup order):
// 2^252 + 27742317777372353535851937790883648493.
var L = func() *big.Int {
	l, ok := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if !ok {
		panic("frost: failed to parse Ed25519 group order")
	}
	return l
}()

// H1 maps an input to a scalar mod L using domain separator "rho".
// Used to derive the per-signer binding factor rho_i (RFC 9591 §4.4).
func H1(m []byte) *big.Int {
	return hashToScalar(ContextString, []byte("rho"), m)
}

// H2 maps an input to a scalar mod L using plain SHA-512 (no FROST prefix).
// This is the Ed25519 challenge hash: c = H2(R || A || M) is byte-identical
// to the hash used by standard Ed25519 verifiers (RFC 8032 §5.1.7 pure mode).
func H2(m []byte) *big.Int {
	sum := sha512.Sum512(m)
	var reduced [32]byte
	edwards25519.ScReduce(&reduced, &sum)
	return scalarFromLE(reduced[:])
}

// H3 maps an input to a scalar mod L using domain separator "nonce".
// Used for deterministic nonce generation (RFC 9591 §4.1, currently unused as
// nonces in this implementation are uniformly random — exposed for callers
// that want the RFC's deterministic construction).
func H3(m []byte) *big.Int {
	return hashToScalar(ContextString, []byte("nonce"), m)
}

// H4 hashes a message under domain separator "msg" and returns the raw 64-byte
// digest (not reduced). Per RFC 9591 §4.4, the digest is fed into H1 as part
// of the binding-factor input.
func H4(m []byte) []byte {
	h := sha512.New()
	h.Write(ContextString)
	h.Write([]byte("msg"))
	h.Write(m)
	return h.Sum(nil)
}

// H5 hashes the encoded commitment list under domain separator "com" and
// returns the raw 64-byte digest. Per RFC 9591 §4.4, the digest is the second
// input to H1 alongside H4(msg).
func H5(m []byte) []byte {
	h := sha512.New()
	h.Write(ContextString)
	h.Write([]byte("com"))
	h.Write(m)
	return h.Sum(nil)
}

// hashToScalar computes SHA-512(prefix || sep || msg) and reduces it mod L.
// The reduction is via ScReduce, the same routine Ed25519 uses internally, so
// the resulting scalar is exactly the value an Ed25519 implementation would
// see when interpreting a 64-byte tag.
func hashToScalar(parts ...[]byte) *big.Int {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	var sum [64]byte
	h.Sum(sum[:0])
	var reduced [32]byte
	edwards25519.ScReduce(&reduced, &sum)
	return scalarFromLE(reduced[:])
}

// EncodeScalar encodes a scalar as 32 bytes little-endian (Ed25519 wire format).
// The scalar is reduced mod L before encoding so callers don't have to pre-reduce.
func EncodeScalar(s *big.Int) []byte {
	r := new(big.Int).Mod(s, L)
	b := r.Bytes()
	out := make([]byte, 32)
	// big.Int.Bytes() is big-endian; reverse into little-endian and zero-pad on the right.
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

// DecodeScalar decodes a 32-byte little-endian Ed25519 scalar.
func DecodeScalar(b []byte) (*big.Int, error) {
	if len(b) != 32 {
		return nil, errors.New("frost: scalar must be 32 bytes")
	}
	s := scalarFromLE(b)
	if s.Cmp(L) >= 0 {
		return nil, errors.New("frost: scalar exceeds group order L")
	}
	return s, nil
}

// scalarFromLE interprets b as a little-endian scalar without bounds checking.
func scalarFromLE(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i, v := range b {
		be[len(b)-1-i] = v
	}
	return new(big.Int).SetBytes(be)
}

// EncodeElement encodes an Ed25519 group element as the canonical 32-byte
// representation specified by RFC 8032 §5.1.2 (little-endian Y with the X
// sign bit packed into the top bit of the last byte).
//
// The input must be on the Ed25519 curve. The output is suitable for use as a
// signature's R component or for hashing into H2/H4/H5.
func EncodeElement(p *crypto.ECPoint) []byte {
	return ecPointToEdwardsCanonical(p.X(), p.Y())
}

// DecodeElement decodes a canonical 32-byte Ed25519 encoding into an ECPoint.
// Returns an error if the encoding is not a valid point on the curve.
func DecodeElement(b []byte) (*crypto.ECPoint, error) {
	if len(b) != 32 {
		return nil, errors.New("frost: element must be 32 bytes")
	}
	var enc [32]byte
	copy(enc[:], b)
	var ge edwards25519.ExtendedGroupElement
	if !ge.FromBytes(&enc) {
		return nil, errors.New("frost: invalid Ed25519 point encoding")
	}
	x, y := extendedToAffine(&ge)
	return crypto.NewECPoint(edwards25519.Edwards(), x, y)
}

// EdwardsCurve returns the registered Ed25519 elliptic curve.
func EdwardsCurve() *edwards25519.TwistedEdwardsCurve {
	return edwards25519.Edwards()
}

// --- private encoding helpers (mirror eddsatss/utils.go) ---

func ecPointToEdwardsCanonical(x, y *big.Int) []byte {
	yLE := bigIntToLE32(y)
	xLE := bigIntToLE32(x)
	var xFE edwards25519.FieldElement
	edwards25519.FeFromBytes(&xFE, xLE)
	negative := edwards25519.FeIsNegative(&xFE) == 1
	out := make([]byte, 32)
	copy(out, yLE[:])
	if negative {
		out[31] |= 1 << 7
	} else {
		out[31] &^= 1 << 7
	}
	return out
}

func bigIntToLE32(a *big.Int) *[32]byte {
	out := new([32]byte)
	if a == nil {
		return out
	}
	be := a.Bytes()
	// Right-pad to 32 bytes (big-endian), then reverse to little-endian.
	if len(be) > 32 {
		// truncate from the left (high-order bytes)
		be = be[len(be)-32:]
	}
	pad := 32 - len(be)
	for i, v := range be {
		out[31-(i+pad)] = v
	}
	return out
}

func extendedToAffine(ge *edwards25519.ExtendedGroupElement) (*big.Int, *big.Int) {
	var enc [32]byte
	ge.ToBytes(&enc)
	// The canonical encoding packs Y in the low 255 bits and X-sign in the top bit.
	// We reconstruct big.Int X and Y by reading FieldElements from ge.
	var x, y, zInv, recipX, recipY edwards25519.FieldElement
	edwards25519.FeInvert(&zInv, &ge.Z)
	edwards25519.FeMul(&recipX, &ge.X, &zInv)
	edwards25519.FeMul(&recipY, &ge.Y, &zInv)
	x = recipX
	y = recipY
	var xBytes, yBytes [32]byte
	edwards25519.FeToBytes(&xBytes, &x)
	edwards25519.FeToBytes(&yBytes, &y)
	return le32ToBigInt(&xBytes), le32ToBigInt(&yBytes)
}

func le32ToBigInt(b *[32]byte) *big.Int {
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[31-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}
