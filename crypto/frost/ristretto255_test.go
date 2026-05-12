package frost

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

)

func TestRistretto255CiphersuiteBasics(t *testing.T) {
	cs := Ristretto255Ciphersuite()
	assert.Equal(t, "ristretto255", cs.Name())
	assert.NotNil(t, cs.Group())
	assert.Equal(t, "ristretto255", cs.Group().Name())

	// All H1..H3 must yield a scalar in [0, L)
	for _, h := range []func([]byte) *big.Int{cs.H1, cs.H2, cs.H3} {
		out := h([]byte("test"))
		require.NotNil(t, out)
		assert.True(t, out.Sign() >= 0)
		assert.True(t, out.Cmp(cs.Group().Order()) < 0)
	}

	// H4 and H5 are raw 64-byte digests.
	assert.Len(t, cs.H4([]byte("x")), 64)
	assert.Len(t, cs.H5([]byte("y")), 64)

	// Different domains must yield different outputs for the same input.
	in := []byte("collision check")
	assert.NotEqual(t, cs.H1(in).Bytes(), cs.H2(in).Bytes(), "H1 vs H2 must differ on same input")
	assert.NotEqual(t, cs.H1(in).Bytes(), cs.H3(in).Bytes(), "H1 vs H3 must differ on same input")

	// FROST(ristretto255) H2 must NOT match FROST(ed25519) H2 (different domain).
	assert.NotEqual(t, cs.H2(in).Bytes(), Ed25519Ciphersuite().H2(in).Bytes(),
		"Ristretto H2 must differ from Ed25519 H2 (Ed25519 has no prefix on H2)")
}

func TestRistretto255BindingFactorsRoundTrip(t *testing.T) {
	cs := Ristretto255Ciphersuite()
	g := cs.Group()

	commitments := make([]NonceCommitment, 3)
	for i := range commitments {
		di := g.RandomScalar(rand.Reader)
		ei := g.RandomScalar(rand.Reader)
		commitments[i] = NonceCommitment{
			Identifier: big.NewInt(int64(i + 1)),
			Hiding:     g.ScalarBaseMult(di),
			Binding:    g.ScalarBaseMult(ei),
		}
	}

	msg := []byte("hello")
	factors := ComputeBindingFactors(cs, msg, commitments)
	require.Len(t, factors, 3)
	for _, c := range commitments {
		rho, ok := factors[c.Identifier.String()]
		require.True(t, ok)
		require.NotNil(t, rho)
		require.True(t, rho.Cmp(g.Order()) < 0)
	}

	R, err := ComputeGroupCommitment(commitments, factors)
	require.NoError(t, err)
	require.NotNil(t, R)
}
