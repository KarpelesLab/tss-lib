package group

import (
	"errors"
	"io"
	"math/big"
)

// Element is a single group element. Implementations are immutable from the
// caller's perspective: every method returns a fresh Element.
//
// All Element implementations belong to a single Group; mixing Elements from
// different groups in Add/ScalarMult will panic (or, at minimum, return
// undefined results). Callers should obtain Elements only via the Group's
// Generator/Identity/DecodeElement/ScalarBaseMult methods, or by calling
// methods on existing Elements.
type Element interface {
	// Add returns the sum self + other.
	Add(other Element) (Element, error)

	// Subtract returns self - other.
	Subtract(other Element) (Element, error)

	// Negate returns -self.
	Negate() Element

	// ScalarMult returns s * self. s is reduced mod Group.Order() implicitly.
	ScalarMult(s *big.Int) Element

	// Equal reports whether self and other represent the same group element.
	Equal(other Element) bool

	// IsIdentity reports whether self is the group identity (0*G).
	IsIdentity() bool

	// Bytes returns the canonical wire encoding of self per the Group's
	// serialization spec. The slice is always Group.ElementBytesLen() bytes.
	Bytes() []byte

	// Clone returns an independent copy of self.
	Clone() Element
}

// Group is a prime-order group abstraction over a finite cyclic group with
// generator G and order Order(). All operations are total (no error returns)
// except element decoding, which can fail on malformed bytes.
type Group interface {
	// Name returns a human-readable group identifier (e.g. "ed25519",
	// "ristretto255"). Used for diagnostics and serialization tagging.
	Name() string

	// Order returns the group order (the prime |G|).
	Order() *big.Int

	// Generator returns the canonical generator G of the group.
	Generator() Element

	// Identity returns the group identity element (0*G).
	Identity() Element

	// ScalarBaseMult returns s*G, where G is Generator().
	ScalarBaseMult(s *big.Int) Element

	// RandomScalar samples a uniformly random scalar in [1, Order()).
	RandomScalar(rand io.Reader) *big.Int

	// ScalarBytesLen returns the length of a canonical scalar encoding.
	ScalarBytesLen() int

	// ElementBytesLen returns the length of a canonical element encoding.
	ElementBytesLen() int

	// EncodeScalar reduces s mod Order() and serializes it canonically. The
	// returned slice has ScalarBytesLen() bytes.
	EncodeScalar(s *big.Int) []byte

	// DecodeScalar parses a canonical scalar encoding back into a *big.Int.
	// Returns an error if the bytes are not a valid encoding (wrong length or
	// out-of-range for canonical-encoding groups).
	DecodeScalar(b []byte) (*big.Int, error)

	// DecodeElement parses a canonical element encoding. Returns an error if
	// the bytes are not a valid encoding. The returned Element is guaranteed
	// to be in the prime-order subgroup (cofactor cleared if applicable).
	DecodeElement(b []byte) (Element, error)
}

// ErrInvalidEncoding is returned by DecodeScalar / DecodeElement when the
// input is not a valid canonical encoding for the group.
var ErrInvalidEncoding = errors.New("group: invalid canonical encoding")
