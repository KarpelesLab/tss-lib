package group

import (
	"errors"
	"io"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// ed25519Group implements Group for the Edwards25519 prime-order subgroup
// used by Ed25519 signatures (and shared with Ristretto255).
//
// Element encoding is the standard 32-byte RFC 8032 form (little-endian Y with
// the X-sign bit packed into the top bit of the last byte).
// Scalar encoding is 32 bytes little-endian.
//
// Elements decoded from bytes are cofactor-cleared (multiplied by 8 then 8^-1)
// so any malicious-but-on-curve point is projected back into the prime-order
// subgroup. Honest Elements produced by ScalarBaseMult or arithmetic on
// already-cleared Elements stay in the subgroup so the clearing is a no-op
// for them.
type ed25519Group struct{}

// Ed25519 returns the singleton Group implementation backed by Edwards25519.
func Ed25519() Group { return ed25519GroupSingleton }

var ed25519GroupSingleton = ed25519Group{}

// ed25519Order is the Edwards25519 group order
// L = 2^252 + 27742317777372353535851937790883648493.
var ed25519Order = func() *big.Int {
	l, ok := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if !ok {
		panic("group: failed to parse Ed25519 order")
	}
	return l
}()

func (ed25519Group) Name() string         { return "ed25519" }
func (ed25519Group) Order() *big.Int      { return new(big.Int).Set(ed25519Order) }
func (ed25519Group) ScalarBytesLen() int  { return 32 }
func (ed25519Group) ElementBytesLen() int { return 32 }

func (ed25519Group) Generator() Element {
	ec := edwards25519.Edwards()
	return &ed25519Element{p: crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)}
}

func (ed25519Group) Identity() Element {
	// Identity on Ed25519 is (0, 1) in affine form.
	ec := edwards25519.Edwards()
	return &ed25519Element{p: crypto.NewECPointNoCurveCheck(ec, big.NewInt(0), big.NewInt(1))}
}

func (g ed25519Group) ScalarBaseMult(s *big.Int) Element {
	red := new(big.Int).Mod(s, ed25519Order)
	if red.Sign() == 0 {
		return g.Identity()
	}
	ec := edwards25519.Edwards()
	return &ed25519Element{p: crypto.ScalarBaseMult(ec, red)}
}

func (ed25519Group) RandomScalar(rand io.Reader) *big.Int {
	return common.GetRandomPositiveInt(rand, ed25519Order)
}

func (ed25519Group) EncodeScalar(s *big.Int) []byte {
	r := new(big.Int).Mod(s, ed25519Order)
	out := make([]byte, 32)
	b := r.Bytes()
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	pad := 32 - len(b)
	for i, v := range b {
		out[31-(i+pad)] = v
	}
	return out
}

func (g ed25519Group) DecodeScalar(b []byte) (*big.Int, error) {
	if len(b) != 32 {
		return nil, errors.New("group/ed25519: scalar must be 32 bytes")
	}
	be := make([]byte, 32)
	for i, v := range b {
		be[31-i] = v
	}
	s := new(big.Int).SetBytes(be)
	if s.Cmp(ed25519Order) >= 0 {
		return nil, errors.New("group/ed25519: scalar >= L")
	}
	return s, nil
}

func (ed25519Group) DecodeElement(b []byte) (Element, error) {
	if len(b) != 32 {
		return nil, errors.New("group/ed25519: element must be 32 bytes")
	}
	var enc [32]byte
	copy(enc[:], b)
	var ge edwards25519.ExtendedGroupElement
	if !ge.FromBytes(&enc) {
		return nil, ErrInvalidEncoding
	}
	x, y := edwardsExtendedToAffine(&ge)
	ec := edwards25519.Edwards()
	p, err := crypto.NewECPoint(ec, x, y)
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	// Cofactor-clear: project potentially-non-prime-order points into the
	// prime-order subgroup. No-op for honest senders.
	p = p.EightInvEight()
	return &ed25519Element{p: p}, nil
}

// AdaptECPoint wraps an existing *crypto.ECPoint (on the Ed25519 curve) as a
// Group Element without going through bytes. The caller asserts the point is
// already in the prime-order subgroup.
func AdaptECPoint(p *crypto.ECPoint) Element {
	return &ed25519Element{p: p}
}

// ECPoint returns the underlying *crypto.ECPoint for an Ed25519 group element,
// or nil if the element is not from the Ed25519 group. This is an escape hatch
// for code that needs to interoperate with the existing crypto.ECPoint-based
// API (e.g. signature verification helpers that expect a *crypto.ECPoint).
func ECPoint(e Element) *crypto.ECPoint {
	if ed, ok := e.(*ed25519Element); ok {
		return ed.p
	}
	return nil
}

// ed25519Element wraps a *crypto.ECPoint. All operations return fresh Elements
// (the input is never mutated).
type ed25519Element struct {
	p *crypto.ECPoint
}

func (e *ed25519Element) Add(other Element) (Element, error) {
	o, ok := other.(*ed25519Element)
	if !ok {
		return nil, errors.New("group/ed25519: Add called with non-Ed25519 element")
	}
	sum, err := e.p.Add(o.p)
	if err != nil {
		return nil, err
	}
	return &ed25519Element{p: sum}, nil
}

func (e *ed25519Element) Subtract(other Element) (Element, error) {
	return e.Add(other.Negate())
}

func (e *ed25519Element) Negate() Element {
	// On a twisted Edwards curve, -P = (-X, Y). Both coordinate negations are
	// taken mod p (the field prime). We work via affine X.
	x := new(big.Int).Sub(edwards25519FieldP, e.p.X())
	x.Mod(x, edwards25519FieldP)
	// IsOnCurve for Ed25519 accepts (P-X, Y) as a valid representative.
	ec := edwards25519.Edwards()
	negPoint := crypto.NewECPointNoCurveCheck(ec, x, e.p.Y())
	return &ed25519Element{p: negPoint}
}

func (e *ed25519Element) ScalarMult(s *big.Int) Element {
	red := new(big.Int).Mod(s, ed25519Order)
	if red.Sign() == 0 {
		return Ed25519().Identity()
	}
	return &ed25519Element{p: e.p.ScalarMult(red)}
}

func (e *ed25519Element) Equal(other Element) bool {
	o, ok := other.(*ed25519Element)
	if !ok {
		return false
	}
	return e.p.Equals(o.p)
}

func (e *ed25519Element) IsIdentity() bool {
	return e.p.X().Sign() == 0 && e.p.Y().Cmp(big.NewInt(1)) == 0
}

func (e *ed25519Element) Bytes() []byte {
	return edwardsAffineToCanonical(e.p.X(), e.p.Y())
}

func (e *ed25519Element) Clone() Element {
	ec := edwards25519.Edwards()
	return &ed25519Element{p: crypto.NewECPointNoCurveCheck(ec, e.p.X(), e.p.Y())}
}

// --- helpers ---

// edwards25519FieldP is the prime 2^255 - 19 for the Curve25519 base field.
var edwards25519FieldP = func() *big.Int {
	p, ok := new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
	if !ok {
		panic("group/ed25519: failed to parse field prime")
	}
	return p
}()

func edwardsAffineToCanonical(x, y *big.Int) []byte {
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
	if len(be) > 32 {
		be = be[len(be)-32:]
	}
	pad := 32 - len(be)
	for i, v := range be {
		out[31-(i+pad)] = v
	}
	return out
}

func edwardsExtendedToAffine(ge *edwards25519.ExtendedGroupElement) (*big.Int, *big.Int) {
	var zInv, recipX, recipY edwards25519.FieldElement
	edwards25519.FeInvert(&zInv, &ge.Z)
	edwards25519.FeMul(&recipX, &ge.X, &zInv)
	edwards25519.FeMul(&recipY, &ge.Y, &zInv)
	var xBytes, yBytes [32]byte
	edwards25519.FeToBytes(&xBytes, &recipX)
	edwards25519.FeToBytes(&yBytes, &recipY)
	return le32ToBigInt(&xBytes), le32ToBigInt(&yBytes)
}

func le32ToBigInt(b *[32]byte) *big.Int {
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[31-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}
