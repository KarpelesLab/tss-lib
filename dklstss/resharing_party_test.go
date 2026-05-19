package dklstss

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestResharingPartyDisjointCommittees: old committee 3-of-3 reshares
// to a disjoint new 3-party committee with threshold 1. End-to-end:
// new committee can sign; old committee shouldn't need to participate
// after round 1.
func TestResharingPartyDisjointCommittees(t *testing.T) {
	const oldN, oldT = 3, 1
	oldPIDs := tss.GenerateTestPartyIDs(oldN)
	oldKeys := runDistributedKeygen(t, oldPIDs, oldT)
	oldPub := oldKeys[0].ECDSAPub

	// New committee with fresh, disjoint IDs.
	newPIDs := genPartyIDsOffset(3, 1000)
	const newT = 1

	// Combined peer context covers both committees.
	combined := make(tss.UnSortedPartyIDs, 0, len(oldPIDs)+len(newPIDs))
	combined = append(combined, oldPIDs...)
	combined = append(combined, newPIDs...)
	combinedSorted := tss.SortPartyIDs(combined)
	combinedCtx := tss.NewPeerContext(combinedSorted)

	// Use OLD subset = {first two old members}, satisfying T+1=2.
	oldSubset := tss.SortedPartyIDs{oldPIDs[0], oldPIDs[1]}

	// Set up hub broker over the combined committee.
	hub := newTestHub(len(combinedSorted))
	pidIdx := map[string]int{}
	for i, p := range combinedSorted {
		pidIdx[p.KeyInt().String()] = i
	}

	// Spawn OLD parties (those in oldSubset, with their oldKey).
	var oldParties []*ResharingParty
	for _, p := range oldSubset {
		// Locate matching index in oldPIDs to fetch oldKey.
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

	// Spawn NEW parties (all of newPIDs, no oldKey). oldPub is the
	// out-of-band-shared public key being resharded.
	var newParties []*ResharingParty
	for _, p := range newPIDs {
		params := tss.NewParameters(tss.S256(), combinedCtx, p, len(combinedSorted), newT)
		params.SetBroker(hub.brokers[pidIdx[p.KeyInt().String()]])
		rp, err := NewResharing(context.Background(), params, oldPub, nil, oldSubset, newPIDs, newT)
		require.NoError(t, err)
		newParties = append(newParties, rp)
	}

	// Wait for new committee to finish.
	newKeys := make([]*Key, len(newPIDs))
	for i, p := range newParties {
		select {
		case k := <-p.Done:
			require.NotNil(t, k, "new-committee key must be non-nil")
			newKeys[i] = k
		case err := <-p.Err:
			t.Fatalf("new party %d failed: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("new party %d timeout", i)
		}
	}

	// Wait for old parties (they should signal nil on Done after round 1).
	for i, p := range oldParties {
		select {
		case k := <-p.Done:
			assert.Nil(t, k, "old-only party should return nil Key (it has no new share)")
		case err := <-p.Err:
			t.Fatalf("old party %d failed: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("old party %d timeout", i)
		}
	}

	// Public key preserved.
	for i, k := range newKeys {
		assert.Truef(t, k.ECDSAPub.Equals(oldPub), "new key %d pubkey differs from old", i)
	}

	// New committee can sign.
	msg := sha256.Sum256([]byte("after-reshare-party sign"))
	sig, err := Sign(newKeys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{Curve: oldPub.Curve(), X: oldPub.X(), Y: oldPub.Y()}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}
