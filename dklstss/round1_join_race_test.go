// Copyright © 2026 KarpelesLab.

package dklstss

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestKeygenPartyRound1JoinNoRace runs N concurrent KeygenParty
// constructions in parallel via the hub broker. Pre-mutex (the
// previous atomic.Int32 pattern) this would race-flag the field
// writes to r1Bcasts / r1Unicasts under the Go race detector. With
// the sync.Mutex protecting the join state, `go test -race` should
// pass cleanly.
//
// The actual race-detection check is performed by `go test -race`
// itself; this test just exercises the concurrent code path.
func TestKeygenPartyRound1JoinNoRace(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*KeygenParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kp, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		parties[i] = kp
	}
	deadline := time.After(5 * time.Minute)
	for i := 0; i < partyCount; i++ {
		select {
		case <-parties[i].Done:
		case e := <-parties[i].Err:
			t.Fatalf("party %d keygen error: %v", i, e)
		case <-deadline:
			t.Fatalf("party %d keygen timed out", i)
		}
	}
}
