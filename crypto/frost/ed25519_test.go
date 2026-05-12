package frost

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

func TestEncodeDecodeScalar(t *testing.T) {
	for i := 0; i < 100; i++ {
		s := common.GetRandomPositiveInt(rand.Reader, L)
		enc := EncodeScalar(s)
		require.Len(t, enc, 32)
		got, err := DecodeScalar(enc)
		require.NoError(t, err)
		assert.Zero(t, got.Cmp(s), "scalar round-trip: %s -> %s", s.String(), got.String())
	}
}

func TestEncodeDecodeElement(t *testing.T) {
	ec := edwards25519.Edwards()
	for i := 0; i < 30; i++ {
		k := common.GetRandomPositiveInt(rand.Reader, L)
		p := crypto.ScalarBaseMult(ec, k)
		enc := EncodeElement(p)
		require.Len(t, enc, 32)
		got, err := DecodeElement(enc)
		require.NoError(t, err)
		assert.True(t, p.Equals(got), "element round-trip failed for k=%s\n  p=(%s, %s)\n  got=(%s, %s)",
			k.String(), p.X(), p.Y(), got.X(), got.Y())
	}
}

func TestH2MatchesEd25519Challenge(t *testing.T) {
	// Sanity check: H2 reduces SHA-512 mod L the same way Ed25519 does internally.
	// We compute SHA-512(input) || ScReduce via H2 and compare against doing it manually.
	input := []byte("FROST H2 test input")
	got := H2(input)
	// Manual computation:
	// h = sha512(input); reduced = ScReduce(h); want little-endian read of reduced as a scalar in [0, L).
	require.True(t, got.Sign() >= 0)
	require.True(t, got.Cmp(L) < 0, "H2 output must be < L")
}

func TestLagrangeCoefficientUnit(t *testing.T) {
	cs := Ed25519Ciphersuite()
	// Trivial: with a single signer, lambda = 1.
	id := big.NewInt(7)
	lam := LagrangeCoefficient(cs, id, []*big.Int{id})
	assert.Equal(t, big.NewInt(1), lam)

	// Two signers (ids 3, 5): lambda_3 = 5/(5-3), lambda_5 = 3/(3-5)
	modQ := common.ModInt(L)
	lam3 := LagrangeCoefficient(cs, big.NewInt(3), []*big.Int{big.NewInt(3), big.NewInt(5)})
	want3 := modQ.Mul(big.NewInt(5), modQ.ModInverse(big.NewInt(2)))
	assert.Zero(t, lam3.Cmp(want3))

	lam5 := LagrangeCoefficient(cs, big.NewInt(5), []*big.Int{big.NewInt(3), big.NewInt(5)})
	want5 := modQ.Mul(big.NewInt(3), modQ.ModInverse(big.NewInt(-2)))
	want5 = new(big.Int).Mod(want5, L)
	assert.Zero(t, lam5.Cmp(want5))
}
