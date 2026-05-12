package group

import (
	"errors"
	"io"
	"math/big"

	"github.com/gtank/ristretto255"

	"github.com/KarpelesLab/tss-lib/v2/common"
)

// ristretto255Group implements Group for Ristretto255 (RFC 9496).
//
// Ristretto255 is a prime-order group built on top of Edwards25519. Its order
// is the same as Ed25519's L, so scalars are interchangeable between the two
// groups at the *big.Int level. Element encoding is 32 bytes canonical per
// RFC 9496 §4.3.4; cofactor clearing is unnecessary because Ristretto255 is
// already prime-order by construction.
type ristretto255Group struct{}

// Ristretto255 returns the singleton Group implementation backed by RFC 9496.
func Ristretto255() Group { return ristretto255GroupSingleton }

var ristretto255GroupSingleton = ristretto255Group{}

func (ristretto255Group) Name() string         { return "ristretto255" }
func (ristretto255Group) Order() *big.Int      { return new(big.Int).Set(ed25519Order) }
func (ristretto255Group) ScalarBytesLen() int  { return 32 }
func (ristretto255Group) ElementBytesLen() int { return 32 }

func (ristretto255Group) Generator() Element {
	return &ristrettoElement{e: ristretto255.NewGeneratorElement()}
}

func (ristretto255Group) Identity() Element {
	return &ristrettoElement{e: ristretto255.NewIdentityElement()}
}

func (g ristretto255Group) ScalarBaseMult(s *big.Int) Element {
	sc := bigIntToRistrettoScalar(s)
	out := ristretto255.NewElement()
	out.ScalarBaseMult(sc)
	return &ristrettoElement{e: out}
}

func (ristretto255Group) RandomScalar(rand io.Reader) *big.Int {
	return common.GetRandomPositiveInt(rand, ed25519Order)
}

func (ristretto255Group) EncodeScalar(s *big.Int) []byte {
	sc := bigIntToRistrettoScalar(s)
	out := make([]byte, 0, 32)
	return sc.Encode(out)
}

func (ristretto255Group) DecodeScalar(b []byte) (*big.Int, error) {
	if len(b) != 32 {
		return nil, errors.New("group/ristretto255: scalar must be 32 bytes")
	}
	sc := ristretto255.NewScalar()
	if _, err := sc.SetCanonicalBytes(b); err != nil {
		return nil, ErrInvalidEncoding
	}
	return ristrettoScalarToBigInt(sc), nil
}

func (ristretto255Group) DecodeElement(b []byte) (Element, error) {
	if len(b) != 32 {
		return nil, errors.New("group/ristretto255: element must be 32 bytes")
	}
	el := ristretto255.NewElement()
	if err := el.Decode(b); err != nil {
		return nil, ErrInvalidEncoding
	}
	return &ristrettoElement{e: el}, nil
}

// ristrettoElement wraps a *ristretto255.Element.
type ristrettoElement struct {
	e *ristretto255.Element
}

func (r *ristrettoElement) Add(other Element) (Element, error) {
	o, ok := other.(*ristrettoElement)
	if !ok {
		return nil, errors.New("group/ristretto255: Add called with non-Ristretto element")
	}
	out := ristretto255.NewElement()
	out.Add(r.e, o.e)
	return &ristrettoElement{e: out}, nil
}

func (r *ristrettoElement) Subtract(other Element) (Element, error) {
	o, ok := other.(*ristrettoElement)
	if !ok {
		return nil, errors.New("group/ristretto255: Subtract called with non-Ristretto element")
	}
	out := ristretto255.NewElement()
	out.Subtract(r.e, o.e)
	return &ristrettoElement{e: out}, nil
}

func (r *ristrettoElement) Negate() Element {
	out := ristretto255.NewElement()
	out.Negate(r.e)
	return &ristrettoElement{e: out}
}

func (r *ristrettoElement) ScalarMult(s *big.Int) Element {
	sc := bigIntToRistrettoScalar(s)
	out := ristretto255.NewElement()
	out.ScalarMult(sc, r.e)
	return &ristrettoElement{e: out}
}

func (r *ristrettoElement) Equal(other Element) bool {
	o, ok := other.(*ristrettoElement)
	if !ok {
		return false
	}
	return r.e.Equal(o.e) == 1
}

func (r *ristrettoElement) IsIdentity() bool {
	return r.e.Equal(ristretto255.NewIdentityElement()) == 1
}

func (r *ristrettoElement) Bytes() []byte {
	return r.e.Encode(make([]byte, 0, 32))
}

func (r *ristrettoElement) Clone() Element {
	out := ristretto255.NewElement()
	out.Set(r.e)
	return &ristrettoElement{e: out}
}

// --- scalar bridge helpers ---

func bigIntToRistrettoScalar(s *big.Int) *ristretto255.Scalar {
	red := new(big.Int).Mod(s, ed25519Order)
	if red.Sign() < 0 {
		red.Add(red, ed25519Order)
	}
	leBytes := make([]byte, 32)
	be := red.Bytes()
	if len(be) > 32 {
		be = be[len(be)-32:]
	}
	pad := 32 - len(be)
	for i, v := range be {
		leBytes[31-(i+pad)] = v
	}
	sc := ristretto255.NewScalar()
	if _, err := sc.SetCanonicalBytes(leBytes); err != nil {
		panic("group/ristretto255: SetCanonicalBytes on reduced scalar should never fail: " + err.Error())
	}
	return sc
}

func ristrettoScalarToBigInt(s *ristretto255.Scalar) *big.Int {
	le := s.Encode(make([]byte, 0, 32))
	be := make([]byte, 32)
	for i, v := range le {
		be[31-i] = v
	}
	return new(big.Int).SetBytes(be)
}
