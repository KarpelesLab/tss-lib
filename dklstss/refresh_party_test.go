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

// TestRefreshPartyEndToEnd: distributed DKG, then distributed refresh,
// then sign with the refreshed shares and verify against the
// (unchanged) public key.
func TestRefreshPartyEndToEnd(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	oldKeys := runDistributedKeygen(t, pIDs, threshold)
	oldPub := oldKeys[0].ECDSAPub

	// Distributed refresh.
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*RefreshParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		rp, err := NewRefresh(context.Background(), params, oldKeys[i])
		require.NoError(t, err)
		parties[i] = rp
	}

	refreshed := make([]*Key, partyCount)
	for i, p := range parties {
		select {
		case k := <-p.Done:
			refreshed[i] = k
		case err := <-p.Err:
			t.Fatalf("refresh party %d failed: %v", i, err)
		case <-time.After(60 * time.Second):
			t.Fatalf("refresh party %d timeout", i)
		}
	}

	// Joint public key preserved.
	for i, k := range refreshed {
		assert.Truef(t, k.ECDSAPub.Equals(oldPub), "party %d pubkey changed", i)
	}

	// Shares actually rotated.
	for i, k := range refreshed {
		assert.NotEqualf(t, oldKeys[i].Xi.String(), k.Xi.String(), "party %d share did not rotate", i)
	}

	// Sign with refreshed shares (using the synchronous Sign for now —
	// signing-via-Party is tested separately).
	msg := sha256.Sum256([]byte("post-refresh-party sign"))
	sig, err := Sign(refreshed, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{Curve: oldPub.Curve(), X: oldPub.X(), Y: oldPub.Y()}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestRefreshPartyOTStateRotates verifies the OT extension Δ value
// differs between old and refreshed keys for the same pair.
func TestRefreshPartyOTStateRotates(t *testing.T) {
	const partyCount, threshold = 2, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	oldKeys := runDistributedKeygen(t, pIDs, threshold)
	oldDelta := oldKeys[0].OT[1].AsBob.Delta()

	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*RefreshParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		rp, err := NewRefresh(context.Background(), params, oldKeys[i])
		require.NoError(t, err)
		parties[i] = rp
	}
	refreshed := make([]*Key, partyCount)
	for i, p := range parties {
		select {
		case k := <-p.Done:
			refreshed[i] = k
		case err := <-p.Err:
			t.Fatalf("party %d failed: %v", i, err)
		case <-time.After(60 * time.Second):
			t.Fatalf("party %d timeout", i)
		}
	}
	newDelta := refreshed[0].OT[1].AsBob.Delta()
	assert.NotEqual(t, oldDelta, newDelta, "OT extension Δ should rotate on refresh")
}
