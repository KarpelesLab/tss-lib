package group

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// groupContract drives a shared test suite against any Group implementation.
// All assertions are framework-level invariants (identity, scalar laws,
// encoding round-trip) so the same body covers Ed25519 and Ristretto255.
func groupContract(t *testing.T, g Group) {
	t.Helper()

	order := g.Order()
	require.NotNil(t, order)
	require.Equal(t, 1, order.Sign(), "Order() must be positive")

	gen := g.Generator()
	id := g.Identity()
	require.True(t, id.IsIdentity())
	require.False(t, gen.IsIdentity())

	// gen + identity == gen
	sum, err := gen.Add(id)
	require.NoError(t, err)
	require.True(t, sum.Equal(gen))

	// 0*G == identity
	zeroG := g.ScalarBaseMult(big.NewInt(0))
	require.True(t, zeroG.IsIdentity(), "0*G must be identity")

	// 1*G == G
	oneG := g.ScalarBaseMult(big.NewInt(1))
	require.True(t, oneG.Equal(gen), "1*G must equal Generator()")

	// (a + b)*G == a*G + b*G for random scalars
	for i := 0; i < 5; i++ {
		a := g.RandomScalar(rand.Reader)
		b := g.RandomScalar(rand.Reader)
		sumScalar := new(big.Int).Add(a, b)
		sumScalar.Mod(sumScalar, order)

		viaSum := g.ScalarBaseMult(sumScalar)
		aG := g.ScalarBaseMult(a)
		bG := g.ScalarBaseMult(b)
		viaParts, err := aG.Add(bG)
		require.NoError(t, err)
		require.True(t, viaSum.Equal(viaParts), "linearity failed at iter %d", i)
	}

	// (a*b)*G == a*(b*G)
	a := g.RandomScalar(rand.Reader)
	b := g.RandomScalar(rand.Reader)
	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, order)
	left := g.ScalarBaseMult(ab)
	right := g.ScalarBaseMult(b).ScalarMult(a)
	require.True(t, left.Equal(right), "associativity (a*b)*G vs a*(b*G) failed")

	// Element encoding round-trip
	for i := 0; i < 10; i++ {
		k := g.RandomScalar(rand.Reader)
		p := g.ScalarBaseMult(k)
		enc := p.Bytes()
		require.Len(t, enc, g.ElementBytesLen())
		got, err := g.DecodeElement(enc)
		require.NoError(t, err)
		require.True(t, p.Equal(got), "element encoding round-trip failed at iter %d", i)
	}

	// Scalar encoding round-trip
	for i := 0; i < 10; i++ {
		s := g.RandomScalar(rand.Reader)
		enc := g.EncodeScalar(s)
		require.Len(t, enc, g.ScalarBytesLen())
		got, err := g.DecodeScalar(enc)
		require.NoError(t, err)
		require.Zero(t, got.Cmp(s), "scalar round-trip failed: %s -> %s", s.String(), got.String())
	}

	// Negate: P + (-P) == identity
	k := g.RandomScalar(rand.Reader)
	p := g.ScalarBaseMult(k)
	neg := p.Negate()
	zero, err := p.Add(neg)
	require.NoError(t, err)
	require.True(t, zero.IsIdentity(), "P + (-P) must be identity")

	// Subtract: P - P == identity
	zero2, err := p.Subtract(p)
	require.NoError(t, err)
	require.True(t, zero2.IsIdentity(), "P - P must be identity")
}

func TestEd25519GroupContract(t *testing.T) {
	groupContract(t, Ed25519())
}

func TestRistretto255GroupContract(t *testing.T) {
	groupContract(t, Ristretto255())
}

func TestEd25519DecodeRejectsTrash(t *testing.T) {
	// 32 bytes that decode to something not a valid point.
	bad := make([]byte, 32)
	bad[0] = 0xff
	bad[31] = 0xff
	_, err := Ed25519().DecodeElement(bad)
	assert.Error(t, err)
}

func TestEd25519AdaptECPointRoundTrip(t *testing.T) {
	g := Ed25519()
	k := g.RandomScalar(rand.Reader)
	e := g.ScalarBaseMult(k)
	pt := ECPoint(e)
	require.NotNil(t, pt)
	adapted := AdaptECPoint(pt)
	assert.True(t, adapted.Equal(e))

	require.Nil(t, ECPoint(Ristretto255().Generator()), "ECPoint on Ristretto255 element returns nil")
}

func TestEd25519MixedGroupAddRejects(t *testing.T) {
	e1 := Ed25519().Generator()
	e2 := Ristretto255().Generator()
	_, err := e1.Add(e2)
	assert.Error(t, err)
}
