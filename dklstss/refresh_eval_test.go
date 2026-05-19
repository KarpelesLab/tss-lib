package dklstss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestEvalCommitmentSumZeroConstHonest verifies the happy-path math:
// given a zero-constant polynomial committed via Vs = [a_1·G, a_2·G, ...]
// and an evaluation point id, the sum at id matches the direct
// evaluation. This guards against regressions in the error-propagation
// rewrite.
func TestEvalCommitmentSumZeroConstHonest(t *testing.T) {
	ec := tss.S256()
	q := ec.Params().N

	// f_self(x) = 3x + 5x^2
	a1 := big.NewInt(3)
	a2 := big.NewInt(5)
	vsSelf := []*crypto.ECPoint{
		crypto.ScalarBaseMult(ec, a1),
		crypto.ScalarBaseMult(ec, a2),
	}

	// f_peer(x) = 7x + 11x^2
	b1 := big.NewInt(7)
	b2 := big.NewInt(11)
	peerVs := map[string][]*crypto.ECPoint{
		"peer1": {
			crypto.ScalarBaseMult(ec, b1),
			crypto.ScalarBaseMult(ec, b2),
		},
	}

	id := big.NewInt(2)

	// Expected: (f_self(2) + f_peer(2)) · G
	// f_self(2) = 3·2 + 5·4 = 26
	// f_peer(2) = 7·2 + 11·4 = 58
	// total = 84
	expected := crypto.ScalarBaseMult(ec, big.NewInt(84))
	_ = q

	got, err := evalCommitmentSumZeroConst(vsSelf, peerVs, id)
	require.NoError(t, err)
	require.True(t, got.Equals(expected), "eval result should match closed-form")
}

// TestEvalCommitmentSumZeroConstEmptyReturnsError verifies the empty-input
// error path is taken instead of silently returning nil.
func TestEvalCommitmentSumZeroConstEmptyReturnsError(t *testing.T) {
	_, err := evalCommitmentSumZeroConst(nil, nil, big.NewInt(1))
	require.Error(t, err)
}

// TestEvalCommitmentSumZeroConstPropagatesAddError ensures that an Add
// error inside the aggregation does not get silently swallowed. We
// construct a peerVs entry whose polynomial evaluation at the chosen id
// produces a point equal to the negative of the self contribution; the
// resulting sum is the curve identity, which ECPoint.Add rejects as
// "off-curve", forcing the error path. Previously this was silently
// dropped via `if err == nil { ... }`.
func TestEvalCommitmentSumZeroConstPropagatesAddError(t *testing.T) {
	ec := tss.S256()

	// f_self(x) = x (a_1=1, no a_2).
	vsSelf := []*crypto.ECPoint{crypto.ScalarBaseMult(ec, big.NewInt(1))}

	// f_peer(x) = -1 · x (a_1 = q-1 ≡ -1 mod q). Then at id=1, f_self+f_peer
	// evaluates to 1 + (-1) = 0 → identity, which ECPoint.Add rejects.
	q := ec.Params().N
	negOne := new(big.Int).Sub(q, big.NewInt(1))
	peerVs := map[string][]*crypto.ECPoint{
		"peer1": {crypto.ScalarBaseMult(ec, negOne)},
	}

	_, err := evalCommitmentSumZeroConst(vsSelf, peerVs, big.NewInt(1))
	require.Error(t, err, "Add error during aggregation must surface, not be silently dropped")
}
