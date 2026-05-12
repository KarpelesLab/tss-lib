package frost

import (
	"crypto/sha512"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
)

// Ristretto255ContextString is the FROST(ristretto255, SHA-512) ciphersuite
// domain separator per RFC 9591 §6.2.4.
var Ristretto255ContextString = []byte("FROST-RISTRETTO255-SHA512-v1")

// ristretto255Ciphersuite implements Ciphersuite for FROST(ristretto255, SHA-512).
//
// Unlike Ed25519, every H1..H5 here includes the FROST domain prefix — there
// is no "compatibility with a stock verifier" constraint forcing a bare hash
// for H2 (Ristretto255 signatures are FROST-specific, not Ed25519).
type ristretto255Ciphersuite struct{}

var ristretto255CSSingleton ristretto255Ciphersuite

// Ristretto255Ciphersuite returns the singleton FROST(ristretto255, SHA-512)
// ciphersuite.
func Ristretto255Ciphersuite() Ciphersuite { return ristretto255CSSingleton }

func (ristretto255Ciphersuite) Name() string          { return "ristretto255" }
func (ristretto255Ciphersuite) Group() group.Group    { return group.Ristretto255() }
func (ristretto255Ciphersuite) ContextString() []byte { return Ristretto255ContextString }

func (ristretto255Ciphersuite) H1(m []byte) *big.Int {
	return ristrettoHashToScalar([]byte("rho"), m)
}
func (ristretto255Ciphersuite) H2(m []byte) *big.Int {
	return ristrettoHashToScalar([]byte("chal"), m)
}
func (ristretto255Ciphersuite) H3(m []byte) *big.Int {
	return ristrettoHashToScalar([]byte("nonce"), m)
}
func (ristretto255Ciphersuite) H4(m []byte) []byte {
	h := sha512.New()
	h.Write(Ristretto255ContextString)
	h.Write([]byte("msg"))
	h.Write(m)
	return h.Sum(nil)
}
func (ristretto255Ciphersuite) H5(m []byte) []byte {
	h := sha512.New()
	h.Write(Ristretto255ContextString)
	h.Write([]byte("com"))
	h.Write(m)
	return h.Sum(nil)
}

// ristrettoHashToScalar computes SHA-512(contextString || tag || msg) and
// reduces it mod L. The reduction uses the same ScReduce routine as Ed25519
// since Ristretto255 inherits Curve25519's scalar order.
func ristrettoHashToScalar(tag, msg []byte) *big.Int {
	h := sha512.New()
	h.Write(Ristretto255ContextString)
	h.Write(tag)
	h.Write(msg)
	var sum [64]byte
	h.Sum(sum[:0])
	var reduced [32]byte
	edwards25519.ScReduce(&reduced, &sum)
	be := make([]byte, 32)
	for i, v := range reduced {
		be[31-i] = v
	}
	return new(big.Int).SetBytes(be)
}
