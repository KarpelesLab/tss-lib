package frostristretto255tss

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
)

// vssCreate produces a Feldman secret sharing of `secret` over the given
// group, returning the polynomial commitments (vs[c] = a_c*G) and the per-id
// shares f(x_id). Equivalent to crypto/vss.Create but works over an arbitrary
// group.Group rather than only elliptic.Curve.
func vssCreate(g group.Group, threshold int, secret *big.Int, ids []*big.Int, rand io.Reader) (vs []group.Element, shares []*vssShare, err error) {
	if threshold < 1 {
		return nil, nil, errors.New("vss threshold < 1")
	}
	if len(ids) < threshold {
		return nil, nil, errors.New("not enough shares to satisfy the threshold")
	}
	if err := checkIndexes(g.Order(), ids); err != nil {
		return nil, nil, err
	}

	poly := samplePolynomial(g.Order(), threshold, secret, rand)
	vs = make([]group.Element, len(poly))
	for c, a := range poly {
		vs[c] = g.ScalarBaseMult(a)
	}
	shares = make([]*vssShare, len(ids))
	for i, id := range ids {
		shares[i] = &vssShare{
			Threshold: threshold,
			ID:        new(big.Int).Set(id),
			Share:     evaluatePolynomial(g.Order(), poly, id),
		}
	}
	return vs, shares, nil
}

// vssShare is a Feldman secret share with its threshold and identifier.
type vssShare struct {
	Threshold int
	ID        *big.Int
	Share     *big.Int
}

// verify checks the share against the Feldman polynomial commitments per
// share.Share * G ?= sum_c (share.ID)^c * vs[c].
func (sh *vssShare) verify(g group.Group, threshold int, vs []group.Element) bool {
	if sh.Threshold != threshold || len(vs) != threshold+1 {
		return false
	}
	modQ := common.ModInt(g.Order())
	v := vs[0].Clone()
	t := big.NewInt(1)
	var err error
	for j := 1; j <= threshold; j++ {
		t = modQ.Mul(t, sh.ID)
		vjt := vs[j].ScalarMult(t)
		v, err = v.Add(vjt)
		if err != nil {
			return false
		}
	}
	want := g.ScalarBaseMult(sh.Share)
	return want.Equal(v)
}

func samplePolynomial(q *big.Int, threshold int, secret *big.Int, rand io.Reader) []*big.Int {
	out := make([]*big.Int, threshold+1)
	out[0] = new(big.Int).Mod(secret, q)
	for i := 1; i <= threshold; i++ {
		out[i] = common.GetRandomPositiveInt(rand, q)
	}
	return out
}

func evaluatePolynomial(q *big.Int, coeffs []*big.Int, id *big.Int) *big.Int {
	modQ := common.ModInt(q)
	result := new(big.Int).Set(coeffs[0])
	X := big.NewInt(1)
	for i := 1; i < len(coeffs); i++ {
		X = modQ.Mul(X, id)
		aiXi := new(big.Int).Mul(coeffs[i], X)
		result = modQ.Add(result, aiXi)
	}
	return result
}

func checkIndexes(q *big.Int, ids []*big.Int) error {
	zero := big.NewInt(0)
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		mod := new(big.Int).Mod(id, q)
		if mod.Cmp(zero) == 0 {
			return errors.New("party index must not be zero")
		}
		s := mod.String()
		if _, ok := seen[s]; ok {
			return errors.New("duplicate party indexes")
		}
		seen[s] = struct{}{}
	}
	return nil
}

// schnorrProof is a non-interactive Schnorr proof of knowledge of x such that
// X = x*G. Encoded over an arbitrary group.Group, with Fiat-Shamir challenge
// derived from a domain-separated SHA-512 of the announcement and the public
// value.
type schnorrProof struct {
	R group.Element // announcement R = k*G
	T *big.Int      // response t = k + c*x mod q
}

// schnorrProve generates a Schnorr proof of knowledge of x with X = x*G.
// Session is mixed into the Fiat-Shamir challenge so proofs are domain-bound
// (use a per-party context string).
func schnorrProve(g group.Group, session []byte, x *big.Int, X group.Element, rand io.Reader) (*schnorrProof, error) {
	if x == nil || X == nil {
		return nil, errors.New("schnorrProve: nil inputs")
	}
	k := g.RandomScalar(rand)
	R := g.ScalarBaseMult(k)
	c := schnorrChallenge(g, session, X, R)
	modQ := common.ModInt(g.Order())
	t := modQ.Add(k, modQ.Mul(c, x))
	return &schnorrProof{R: R, T: t}, nil
}

// schnorrVerify verifies a Schnorr proof: t*G ?= R + c*X.
func schnorrVerify(g group.Group, session []byte, X group.Element, proof *schnorrProof) bool {
	if proof == nil || proof.R == nil || proof.T == nil || X == nil {
		return false
	}
	c := schnorrChallenge(g, session, X, proof.R)
	lhs := g.ScalarBaseMult(proof.T)
	rhs, err := proof.R.Add(X.ScalarMult(c))
	if err != nil {
		return false
	}
	return lhs.Equal(rhs)
}

// commitElements builds a hash commitment over a list of group elements:
// commit = SHA-512(randomness || encode(elements[0]) || encode(elements[1]) || ...)
// The decommit value is randomness || encoded elements (concatenated).
// Used by resharing to commit to a polynomial-of-elements without going
// through cmts.NewHashCommitment's *big.Int marshaling, which has length
// ambiguity for 32-byte canonical encodings with leading zeros.
func commitElements(rand io.Reader, elements []group.Element) (commit, decommit []byte, err error) {
	randomness := make([]byte, 32)
	if _, err := io.ReadFull(rand, randomness); err != nil {
		return nil, nil, err
	}
	decommit = make([]byte, 0, 32+len(elements)*32)
	decommit = append(decommit, randomness...)
	for _, e := range elements {
		enc := e.Bytes()
		if len(enc) != 32 {
			return nil, nil, fmt.Errorf("commitElements: element encoding must be 32 bytes, got %d", len(enc))
		}
		decommit = append(decommit, enc...)
	}
	h := sha512.New()
	h.Write(decommit)
	commit = h.Sum(nil)
	return commit, decommit, nil
}

// verifyCommitElements verifies a (commit, decommit) pair and recovers the
// element list. Returns (ok, elements, error). ok is false if the commit
// doesn't match, error is non-nil for decode failures (malformed bytes,
// wrong length).
func verifyCommitElements(g group.Group, commit, decommit []byte, count int) (bool, []group.Element, error) {
	if len(decommit) != 32+count*32 {
		return false, nil, fmt.Errorf("verifyCommitElements: decommit wrong length: got %d, want %d", len(decommit), 32+count*32)
	}
	h := sha512.New()
	h.Write(decommit)
	expected := h.Sum(nil)
	if !bytes.Equal(expected, commit) {
		return false, nil, nil
	}
	out := make([]group.Element, count)
	for i := 0; i < count; i++ {
		enc := decommit[32+i*32 : 32+(i+1)*32]
		el, err := g.DecodeElement(enc)
		if err != nil {
			return false, nil, fmt.Errorf("verifyCommitElements: decode element %d: %w", i, err)
		}
		out[i] = el
	}
	return true, out, nil
}

// schnorrChallenge is the Fiat-Shamir challenge function shared by
// schnorrProve and schnorrVerify. The hash is the FROST-Ristretto255-style
// domain-separated SHA-512 of the session, public value, and announcement,
// reduced mod the group order via ScReduce.
func schnorrChallenge(g group.Group, session []byte, X, R group.Element) *big.Int {
	h := sha512.New()
	h.Write(frost.Ristretto255ContextString)
	h.Write([]byte("schnorr-pok"))
	h.Write(session)
	h.Write(X.Bytes())
	h.Write(R.Bytes())
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
