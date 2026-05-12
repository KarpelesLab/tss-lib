package frost

import (
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
)

// ContextString is the FROST(Ed25519, SHA-512) ciphersuite domain separator
// per RFC 9591 §6.1.4. It is mixed into all FROST-specific hashes (H1, H3,
// H4, H5) but deliberately NOT into H2 — H2 is the plain Ed25519 challenge
// hash so FROST(Ed25519) signatures verify under any Ed25519 verifier.
var ContextString = []byte("FROST-ED25519-SHA512-v1")

// L is the Ed25519 group order (same as Ristretto255 order):
// 2^252 + 27742317777372353535851937790883648493.
var L = func() *big.Int {
	l, ok := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if !ok {
		panic("frost: failed to parse Ed25519 group order")
	}
	return l
}()

// ed25519Ciphersuite implements Ciphersuite for FROST(Ed25519, SHA-512).
type ed25519Ciphersuite struct{}

var ed25519CSSingleton ed25519Ciphersuite

// Ed25519Ciphersuite returns the singleton FROST(Ed25519, SHA-512) ciphersuite.
func Ed25519Ciphersuite() Ciphersuite { return ed25519CSSingleton }

func (ed25519Ciphersuite) Name() string          { return "ed25519" }
func (ed25519Ciphersuite) Group() group.Group    { return group.Ed25519() }
func (ed25519Ciphersuite) ContextString() []byte { return ContextString }
func (ed25519Ciphersuite) H1(m []byte) *big.Int  { return H1(m) }
func (ed25519Ciphersuite) H2(m []byte) *big.Int  { return H2(m) }
func (ed25519Ciphersuite) H3(m []byte) *big.Int  { return H3(m) }
func (ed25519Ciphersuite) H4(m []byte) []byte    { return H4(m) }
func (ed25519Ciphersuite) H5(m []byte) []byte    { return H5(m) }

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
func H3(m []byte) *big.Int {
	return hashToScalar(ContextString, []byte("nonce"), m)
}

// H4 hashes a message under domain separator "msg" and returns the raw 64-byte
// digest. Per RFC 9591 §4.4, the digest is fed into H1 as part of the
// binding-factor input.
func H4(m []byte) []byte {
	h := sha512.New()
	h.Write(ContextString)
	h.Write([]byte("msg"))
	h.Write(m)
	return h.Sum(nil)
}

// H5 hashes the encoded commitment list under domain separator "com" and
// returns the raw 64-byte digest.
func H5(m []byte) []byte {
	h := sha512.New()
	h.Write(ContextString)
	h.Write([]byte("com"))
	h.Write(m)
	return h.Sum(nil)
}

// hashToScalar computes SHA-512(parts...) and reduces mod L via ScReduce.
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

// EncodeScalar encodes a scalar as 32 bytes little-endian (Ed25519 wire
// format). Equivalent to group.Ed25519().EncodeScalar; kept as a top-level
// helper for backwards compatibility with the Phase-1 API.
func EncodeScalar(s *big.Int) []byte { return group.Ed25519().EncodeScalar(s) }

// DecodeScalar decodes a 32-byte little-endian Ed25519 scalar.
func DecodeScalar(b []byte) (*big.Int, error) {
	if len(b) != 32 {
		return nil, errors.New("frost: scalar must be 32 bytes")
	}
	return group.Ed25519().DecodeScalar(b)
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
// representation. Equivalent to group.AdaptECPoint(p).Bytes().
func EncodeElement(p *crypto.ECPoint) []byte {
	return group.AdaptECPoint(p).Bytes()
}

// DecodeElement decodes a canonical 32-byte Ed25519 encoding into a
// *crypto.ECPoint. Returns an error if the encoding is invalid. Includes
// cofactor clearing per group.Ed25519().DecodeElement semantics.
func DecodeElement(b []byte) (*crypto.ECPoint, error) {
	el, err := group.Ed25519().DecodeElement(b)
	if err != nil {
		return nil, err
	}
	return group.ECPoint(el), nil
}

// EdwardsCurve returns the registered Ed25519 elliptic curve. Kept for
// backwards compatibility with Phase-1 callers.
func EdwardsCurve() *edwards25519.TwistedEdwardsCurve {
	return edwards25519.Edwards()
}
