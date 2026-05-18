package dklstss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestNewECPointRejectsSecp256k1Identity locks in the property that the
// signing/presign K_j decode paths reject the curve identity (0, 0). On
// secp256k1 the identity is represented as (0, 0) — IsOnCurve returns
// false for it, so crypto.NewECPoint refuses to construct one. This means
// the round-1 K_j decode in dklstss/signing_party.go and
// dklstss/presign_party.go cannot accept a peer's identity-K_j contribution.
//
// For cofactor>1 curves this would not suffice, but dklstss is secp256k1-only.
func TestNewECPointRejectsSecp256k1Identity(t *testing.T) {
	ec := tss.S256()
	_, err := crypto.NewECPoint(ec, big.NewInt(0), big.NewInt(0))
	require.Error(t, err, "NewECPoint must reject the (0, 0) identity on secp256k1")
}

// TestNewECPointRejectsZeroX is a complementary check: any point with
// X=0 is also rejected (no on-curve X=0 point exists on secp256k1).
func TestNewECPointRejectsZeroX(t *testing.T) {
	ec := tss.S256()
	_, err := crypto.NewECPoint(ec, big.NewInt(0), big.NewInt(1))
	require.Error(t, err)
}
