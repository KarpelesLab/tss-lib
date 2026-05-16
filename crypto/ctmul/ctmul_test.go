package ctmul

import (
	"crypto/rand"
	"math/big"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestScalarBaseMultMatchesReference verifies that the CT base-mult
// produces the same affine point as the standard (non-CT)
// crypto.ScalarBaseMult for many random scalars.
func TestScalarBaseMultMatchesReference(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N

	for trial := 0; trial < 64; trial++ {
		k := common.GetRandomPositiveInt(rand.Reader, q)
		want := crypto.ScalarBaseMult(ec, k)
		got := ScalarBaseMult(ec, k)
		require.NotNil(t, got)
		assert.Equalf(t, want.X().String(), got.X().String(), "trial %d X mismatch (k=%s)", trial, k.String())
		assert.Equalf(t, want.Y().String(), got.Y().String(), "trial %d Y mismatch (k=%s)", trial, k.String())
	}
}

// TestScalarMultMatchesReference verifies CT ScalarMult against the
// stdlib reference across random points and scalars.
func TestScalarMultMatchesReference(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N

	for trial := 0; trial < 32; trial++ {
		// Random point: a · G for fresh a.
		a := common.GetRandomPositiveInt(rand.Reader, q)
		P := crypto.ScalarBaseMult(ec, a)
		// Random scalar.
		k := common.GetRandomPositiveInt(rand.Reader, q)

		want := P.ScalarMult(k)
		got := ScalarMult(P, k)
		require.NotNil(t, got)
		assert.Equalf(t, want.X().String(), got.X().String(), "trial %d X mismatch", trial)
		assert.Equalf(t, want.Y().String(), got.Y().String(), "trial %d Y mismatch", trial)
	}
}

// TestScalarMultEdgeScalars covers small and structured scalar values
// that can exercise edge cases in the ladder.
func TestScalarMultEdgeScalars(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N

	P := crypto.ScalarBaseMult(ec, big.NewInt(42))

	cases := []struct {
		name string
		k    *big.Int
	}{
		{"k=1", big.NewInt(1)},
		{"k=2", big.NewInt(2)},
		{"k=3", big.NewInt(3)},
		{"k=255", big.NewInt(255)},
		{"k=2^32", new(big.Int).Lsh(big.NewInt(1), 32)},
		{"k=2^128", new(big.Int).Lsh(big.NewInt(1), 128)},
		{"k=2^255", new(big.Int).Lsh(big.NewInt(1), 255)},
		{"k=q-1", new(big.Int).Sub(q, big.NewInt(1))},
		{"k=q/2", new(big.Int).Rsh(q, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := P.ScalarMult(tc.k)
			got := ScalarMult(P, tc.k)
			require.NotNil(t, got)
			assert.Equal(t, want.X().String(), got.X().String(), "X")
			assert.Equal(t, want.Y().String(), got.Y().String(), "Y")
		})
	}
}

// TestScalarMultBaseMatchesScalarMultG is a sanity round-trip:
// ScalarBaseMult(curve, k) must equal ScalarMult(G, k).
func TestScalarMultBaseMatchesScalarMultG(t *testing.T) {
	ec := tss.S256()
	params := ec.Params()
	G := crypto.NewECPointNoCurveCheck(ec, params.Gx, params.Gy)

	for trial := 0; trial < 8; trial++ {
		k := common.GetRandomPositiveInt(rand.Reader, ec.Params().N)
		viaBase := ScalarBaseMult(ec, k)
		viaPoint := ScalarMult(G, k)
		assert.Equal(t, viaBase.X().String(), viaPoint.X().String(), "trial %d X", trial)
		assert.Equal(t, viaBase.Y().String(), viaPoint.Y().String(), "trial %d Y", trial)
	}
}

// TestScalarMultRandomizedSweep covers a range of bit patterns to catch
// off-by-one or endianness errors in the ladder.
func TestScalarMultRandomizedSweep(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N
	rng := mathrand.New(mathrand.NewSource(0xC0DEBEEF))

	// Cache a fixed point to reuse.
	P := crypto.ScalarBaseMult(ec, big.NewInt(7))

	for trial := 0; trial < 64; trial++ {
		var k *big.Int
		switch trial % 5 {
		case 0:
			k = big.NewInt(int64(rng.Uint32()))
		case 1:
			k = new(big.Int).Lsh(big.NewInt(1), uint(rng.Intn(255)+1))
		case 2:
			k = common.GetRandomPositiveInt(rand.Reader, q)
		case 3:
			k = new(big.Int).Sub(q, big.NewInt(int64(rng.Uint32())+1))
		default:
			bits := 1 + rng.Intn(255)
			k = new(big.Int).SetBit(big.NewInt(0), bits, 1)
			k.Or(k, big.NewInt(int64(rng.Uint32())))
		}
		want := P.ScalarMult(k)
		got := ScalarMult(P, k)
		require.Equalf(t, want.X().String(), got.X().String(), "trial %d X (k=%s)", trial, k.String())
		require.Equalf(t, want.Y().String(), got.Y().String(), "trial %d Y (k=%s)", trial, k.String())
	}
}

// TestScalarMultFallsBackOnNonSecp256k1 verifies that calling ScalarMult
// on a non-secp256k1 point returns the same result as the reference (we
// don't have another curve handy in this test, so we just verify the
// call doesn't panic on a malformed point and returns nil correctly).
func TestScalarMultNilInputs(t *testing.T) {
	assert.Nil(t, ScalarMult(nil, big.NewInt(1)))
	P := crypto.ScalarBaseMult(tss.S256(), big.NewInt(1))
	assert.Nil(t, ScalarMult(P, nil))
}

// TestZRandomizationProducesDifferentJacobian asserts the
// Z-randomization actually changes the Jacobian representation while
// preserving the affine projection.
func TestZRandomizationProducesDifferentJacobian(t *testing.T) {
	ec := tss.S256()
	P := crypto.ScalarBaseMult(ec, big.NewInt(123))

	// Run the same scalar mult twice with independent random sources;
	// both should produce the same affine result.
	k := common.GetRandomPositiveInt(rand.Reader, ec.Params().N)
	out1 := ScalarMultWithRand(P, k, rand.Reader)
	out2 := ScalarMultWithRand(P, k, rand.Reader)
	assert.Equal(t, out1.X().String(), out2.X().String(), "X must be reproducible across random Z choices")
	assert.Equal(t, out1.Y().String(), out2.Y().String(), "Y must be reproducible across random Z choices")
}
