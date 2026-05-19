package dklstss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestVerifyZeroConstShareRejectsInvalidPoint guards against a malformed
// V[k] crashing the verification path. The fix ensures V.ValidateBasic()
// is checked before ScalarMult, which would otherwise panic on (0,0) or
// off-curve coordinates.
func TestVerifyZeroConstShareRejectsInvalidPoint(t *testing.T) {
	ec := tss.S256()
	// Valid coefficient.
	good := crypto.ScalarBaseMult(ec, big.NewInt(3))
	// Crafted "point" with nil coordinates (caller bypassed NewECPoint).
	bad := crypto.NewECPointNoCurveCheck(ec, nil, nil)

	require.False(t, verifyZeroConstShare([]*crypto.ECPoint{good, bad}, big.NewInt(1), big.NewInt(1)),
		"invalid V[k] must cause verification to fail, not panic")
}

// TestVerifyZeroConstShareRejectsZeroID guards against id ≡ 0 mod q,
// which would otherwise cause ScalarMult(idPow=0) to panic.
func TestVerifyZeroConstShareRejectsZeroID(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N
	good := crypto.ScalarBaseMult(ec, big.NewInt(3))

	require.False(t, verifyZeroConstShare([]*crypto.ECPoint{good}, big.NewInt(0), big.NewInt(1)))
	require.False(t, verifyZeroConstShare([]*crypto.ECPoint{good}, q, big.NewInt(1)),
		"id == q must be rejected (mods to 0)")
}

// TestEvalCommitmentSumZeroConstRejectsInvalidPeerPoint verifies the
// equivalent guard in evalCommitmentSumZeroConst.
func TestEvalCommitmentSumZeroConstRejectsInvalidPeerPoint(t *testing.T) {
	ec := tss.S256()
	vsSelf := []*crypto.ECPoint{crypto.ScalarBaseMult(ec, big.NewInt(3))}
	// Peer ships a polynomial commitment whose first entry is malformed.
	bad := crypto.NewECPointNoCurveCheck(ec, nil, nil)
	peerVs := map[string][]*crypto.ECPoint{"peer1": {bad}}

	_, err := evalCommitmentSumZeroConst(vsSelf, peerVs, big.NewInt(1))
	require.Error(t, err, "malformed peer commitment must be rejected, not panic")
}
