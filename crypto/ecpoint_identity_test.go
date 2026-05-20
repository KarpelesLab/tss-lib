// Copyright © 2026 KarpelesLab.

package crypto_test

import (
	"math/big"
	"testing"

	"github.com/KarpelesLab/edwards25519"
	"github.com/stretchr/testify/require"

	. "github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestECPointIsIdentityNilSafe ensures the helper does not panic on nil.
func TestECPointIsIdentityNilSafe(t *testing.T) {
	var p *ECPoint
	require.False(t, p.IsIdentity())
}

// TestECPointIsIdentityShortWeierstrass: secp256k1 identity is (0, 0). It
// is NOT on the curve, so NewECPoint rejects it. We must construct via the
// no-check path to exercise IsIdentity for short-Weierstrass identity.
func TestECPointIsIdentityShortWeierstrass(t *testing.T) {
	ec := tss.S256()
	id := NewECPointNoCurveCheck(ec, big.NewInt(0), big.NewInt(0))
	require.True(t, id.IsIdentity(), "(0,0) must be reported as identity")

	// A non-identity secp256k1 point: G itself.
	gx, gy := ec.Params().Gx, ec.Params().Gy
	g, err := NewECPoint(ec, gx, gy)
	require.NoError(t, err)
	require.False(t, g.IsIdentity())
}

// TestECPointIsIdentityTwistedEdwards: Ed25519 identity is (0, 1) and IS on
// the curve. NewECPoint accepts it; IsIdentity must detect it.
func TestECPointIsIdentityTwistedEdwards(t *testing.T) {
	ec := edwards25519.Edwards()
	id, err := NewECPoint(ec, big.NewInt(0), big.NewInt(1))
	require.NoError(t, err)
	require.True(t, id.IsIdentity(), "(0,1) must be reported as identity on Ed25519")

	// Base point Bx = ec.Params().Gx, By = ec.Params().Gy — non-identity.
	g, err := NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	require.NoError(t, err)
	require.False(t, g.IsIdentity())
}

// TestECPointIsIdentityXSetYZeroNonStandard: a point with X≠0 must never
// be identity regardless of Y.
func TestECPointIsIdentityXNotZero(t *testing.T) {
	ec := tss.S256()
	p := NewECPointNoCurveCheck(ec, big.NewInt(5), big.NewInt(0))
	require.False(t, p.IsIdentity())
	p2 := NewECPointNoCurveCheck(ec, big.NewInt(5), big.NewInt(1))
	require.False(t, p2.IsIdentity())
}
