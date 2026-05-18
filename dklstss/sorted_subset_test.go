package dklstss

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestValidateSortedSubsetAccepts verifies the happy path.
func TestValidateSortedSubsetAccepts(t *testing.T) {
	ids := tss.GenerateTestPartyIDs(5)
	require.NoError(t, validateSortedSubset(ids))
}

// TestValidateSortedSubsetRejectsUnordered verifies unsorted input is
// rejected.
func TestValidateSortedSubsetRejectsUnordered(t *testing.T) {
	ids := tss.GenerateTestPartyIDs(3)
	bad := tss.SortedPartyIDs{ids[1], ids[0], ids[2]}
	err := validateSortedSubset(bad)
	require.Error(t, err)
}

// TestValidateSortedSubsetRejectsDuplicate verifies duplicate IDs are
// rejected. The strict-ascending check (>=) catches this.
func TestValidateSortedSubsetRejectsDuplicate(t *testing.T) {
	ids := tss.GenerateTestPartyIDs(2)
	dup := tss.SortedPartyIDs{ids[0], ids[0]}
	err := validateSortedSubset(dup)
	require.Error(t, err)
}

// TestNewSigningRejectsUnsortedSubset verifies that NewSigning surfaces
// the sortedness violation. With T+1 ≥ 2 a swap is observable.
func TestNewSigningRejectsUnsortedSubset(t *testing.T) {
	const N, T = 3, 1
	pIDs := genPartyIDs(N)
	keys, err := Keygen(N, T, pIDs, rand.Reader)
	require.NoError(t, err)

	// Build a subset of size 2 (T+1) in reversed order.
	subset := tss.SortedPartyIDs{pIDs[1], pIDs[0]}
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	p2pCtx := tss.NewPeerContext(pIDs)
	params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], N, T)

	_, err = NewSigning(context.Background(), params, keys[0], hash, subset, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not strictly ascending")
	_ = big.NewInt
}

// TestNewPresignRejectsUnsortedSubset mirrors the above for NewPresign.
func TestNewPresignRejectsUnsortedSubset(t *testing.T) {
	const N, T = 3, 1
	pIDs := genPartyIDs(N)
	keys, err := Keygen(N, T, pIDs, rand.Reader)
	require.NoError(t, err)

	subset := tss.SortedPartyIDs{pIDs[1], pIDs[0]}
	p2pCtx := tss.NewPeerContext(pIDs)
	params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], N, T)

	_, err = NewPresign(context.Background(), params, keys[0], subset)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not strictly ascending")
}
