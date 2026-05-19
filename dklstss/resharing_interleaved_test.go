package dklstss

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestResharingPartyInterleavedCommitteeKeys is a regression test for a
// real bug found in production: `dklstss/resharing_party.go` indexed
// newBigXj[*] and ot[*] by `pj.Index`, the position of pj in the
// COMBINED OLD+NEW peer context. For most test setups this happens to
// equal the position within newSubset (because the test's OLD keys
// either all sort before or all sort after the NEW keys), but a
// real-world setup that derives party keys from random identifiers
// (e.g., 16-byte UUIDs) will interleave OLD and NEW parties in the
// combined sort — pushing some pj.Index values outside [0, len(newSubset))
// and causing an `index out of range` panic in finalize.
//
// This test forces the interleaved case with the keyset
//
//	OLD = {10, 20, 30}, NEW = {15, 25, 35}
//
// whose combined sort is [10, 15, 20, 25, 30, 35], placing every NEW
// party's combined-context Index at 1, 3, or 5 — all >= len(newSubset)=3.
// Under the previous code the test panicked; with the fix it completes.
func TestResharingPartyInterleavedCommitteeKeys(t *testing.T) {
	const oldT, newT = 1, 1

	// Generate OLD keys FIRST, in a fresh stand-alone context. tss.SortPartyIDs
	// mutates the Index field on the PartyID pointers it sorts; we must
	// not reuse the same PartyID pointers across the keygen context AND
	// the combined-reshare context, or the second sort silently shifts
	// the indexes the first context's broker depends on. Use fresh
	// PartyID instances (same keys) for the reshare phase below.
	oldKeygenPIDs := makeKeyedPartyIDs([]int{10, 20, 30})
	oldKeys := runDistributedKeygen(t, oldKeygenPIDs, oldT)
	oldPub := oldKeys[0].ECDSAPub

	// Build OLD + NEW for the reshare phase with fresh PartyID instances
	// (so their Index fields can be assigned by the combined sort
	// without disturbing the keygen context).
	oldPIDs := makeKeyedPartyIDs([]int{10, 20, 30})
	newPIDs := makeKeyedPartyIDs([]int{15, 25, 35})

	combined := append(tss.UnSortedPartyIDs{}, oldPIDs...)
	combined = append(combined, newPIDs...)
	combinedSorted := tss.SortPartyIDs(combined)
	// Sanity: combined sort interleaves OLD and NEW. Every NEW party's
	// pj.Index is then 1, 3, or 5 — all >= len(newSubset)=3 — exactly
	// the case that panicked under the old pj.Index-based indexing.
	require.Equal(t, "10", combinedSorted[0].KeyInt().String())
	require.Equal(t, "15", combinedSorted[1].KeyInt().String())
	require.Equal(t, "20", combinedSorted[2].KeyInt().String())
	require.Equal(t, "25", combinedSorted[3].KeyInt().String())
	require.Equal(t, "30", combinedSorted[4].KeyInt().String())
	require.Equal(t, "35", combinedSorted[5].KeyInt().String())

	combinedCtx := tss.NewPeerContext(combinedSorted)
	oldSubset := tss.SortedPartyIDs{oldPIDs[0], oldPIDs[1]}

	hub := newTestHub(len(combinedSorted))
	pidIdx := map[string]int{}
	for i, p := range combinedSorted {
		pidIdx[p.KeyInt().String()] = i
	}

	// OLD parties.
	var oldParties []*ResharingParty
	for _, p := range oldSubset {
		oldIdx := -1
		for i, q := range oldPIDs {
			if q.KeyInt().Cmp(p.KeyInt()) == 0 {
				oldIdx = i
				break
			}
		}
		params := tss.NewParameters(tss.S256(), combinedCtx, p, len(combinedSorted), oldT)
		params.SetBroker(hub.brokers[pidIdx[p.KeyInt().String()]])
		rp, err := NewResharing(context.Background(), params, oldPub, oldKeys[oldIdx], oldSubset, newPIDs, newT)
		require.NoError(t, err)
		oldParties = append(oldParties, rp)
	}

	// NEW parties.
	var newParties []*ResharingParty
	for _, p := range newPIDs {
		params := tss.NewParameters(tss.S256(), combinedCtx, p, len(combinedSorted), newT)
		params.SetBroker(hub.brokers[pidIdx[p.KeyInt().String()]])
		rp, err := NewResharing(context.Background(), params, oldPub, nil, oldSubset, newPIDs, newT)
		require.NoError(t, err)
		newParties = append(newParties, rp)
	}

	// Wait for new committee.
	newKeys := make([]*Key, len(newPIDs))
	for i, p := range newParties {
		select {
		case k := <-p.Done:
			require.NotNilf(t, k, "new party %d returned nil key", i)
			newKeys[i] = k
		case err := <-p.Err:
			t.Fatalf("new party %d failed: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("new party %d timeout", i)
		}
	}

	for i, p := range oldParties {
		select {
		case k := <-p.Done:
			assert.Nil(t, k, "old-only party should return nil Key")
		case err := <-p.Err:
			t.Fatalf("old party %d failed: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("old party %d timeout", i)
		}
	}

	// Public key preserved across all new committee members.
	for i, k := range newKeys {
		assert.Truef(t, k.ECDSAPub.Equals(oldPub), "new key %d pubkey differs from old", i)
		// Idx must be the position within newSubset, NOT within the
		// combined context. This is the property the indexing fix
		// preserves.
		assert.Equalf(t, i, k.Idx,
			"new key %d Idx must be its position in newSubset, got %d", i, k.Idx)
	}

	// New committee can sign and the signature verifies under the
	// original pubkey via stdlib ECDSA.
	msg := sha256.Sum256([]byte("interleaved reshare sign"))
	sig, err := Sign(newKeys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{Curve: oldPub.Curve(), X: oldPub.X(), Y: oldPub.Y()}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// makeKeyedPartyIDs returns SortedPartyIDs whose KeyInt() values equal
// the provided integers (after SortPartyIDs's sort + index assignment).
func makeKeyedPartyIDs(ks []int) tss.SortedPartyIDs {
	unsorted := make(tss.UnSortedPartyIDs, len(ks))
	for i, k := range ks {
		unsorted[i] = tss.NewPartyID(
			"k-"+strconv.Itoa(k),
			"moniker-"+strconv.Itoa(k),
			big.NewInt(int64(k)),
		)
	}
	return tss.SortPartyIDs(unsorted)
}
