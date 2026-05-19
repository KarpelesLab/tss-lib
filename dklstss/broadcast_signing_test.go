package dklstss

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// observingBroker counts To==nil vs To!=nil sends for a tagged message type.
// Wraps an underlying hubBroker so the routed behavior is preserved.
type observingBroker struct {
	*hubBroker
	tag          string
	bcastCount   int
	unicastCount int
}

func (b *observingBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From != nil && msg.From.Index == b.partyIdx && msg.Type == b.tag {
		if msg.To == nil {
			b.bcastCount++
		} else {
			b.unicastCount++
		}
	}
	return b.hubBroker.Receive(msg)
}

// TestSigningRound1IsBroadcast asserts that the signing-round-1 K_i
// message is delivered as a single To==nil broadcast rather than N-1
// per-recipient unicasts. The conversion is an equivocation-defense
// fix — a true broadcast lets a well-behaved broker enforce "same bytes
// to every recipient" rather than allowing N independent payloads.
func TestSigningRound1IsBroadcast(t *testing.T) {
	const N, T = 3, 1
	pIDs := genPartyIDs(N)
	keys, err := Keygen(N, T, pIDs, rand.Reader)
	require.NoError(t, err)

	hub := newTestHub(N)
	observers := make([]*observingBroker, N)
	for i := 0; i < N; i++ {
		observers[i] = &observingBroker{hubBroker: hub.brokers[i], tag: "dkls:sign:r1"}
	}

	subset := tss.SortedPartyIDs{pIDs[0], pIDs[1]}
	hash := sha256.Sum256([]byte("test-r1-broadcast"))
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*SigningParty, 2)
	for i, partyIdx := range []int{0, 1} {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[partyIdx], N, T)
		params.SetBroker(observers[partyIdx])
		sp, err := NewSigning(context.Background(), params, keys[partyIdx], hash[:], subset, nil)
		require.NoError(t, err)
		parties[i] = sp
	}

	// Wait for signing to complete (success required for the test to be
	// meaningful — proves that broadcast actually works end-to-end).
	for _, sp := range parties {
		select {
		case <-sp.Done:
		case err := <-sp.Err:
			t.Fatalf("signing failed: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatalf("signing timeout")
		}
	}

	// Each signer in the subset {0, 1} should have sent exactly ONE
	// broadcast for the r1 K_i message — not N-1 unicasts.
	for _, partyIdx := range []int{0, 1} {
		require.Equalf(t, 1, observers[partyIdx].bcastCount,
			"party %d should have sent exactly 1 broadcast for r1", partyIdx)
		require.Equalf(t, 0, observers[partyIdx].unicastCount,
			"party %d should not have sent any r1 unicasts", partyIdx)
	}
}

// TestPresignRound1IsBroadcast mirrors the above for the presign-round-1
// K_i broadcast.
func TestPresignRound1IsBroadcast(t *testing.T) {
	const N, T = 3, 1
	pIDs := genPartyIDs(N)
	keys, err := Keygen(N, T, pIDs, rand.Reader)
	require.NoError(t, err)

	hub := newTestHub(N)
	observers := make([]*observingBroker, N)
	for i := 0; i < N; i++ {
		observers[i] = &observingBroker{hubBroker: hub.brokers[i], tag: "dkls:presign:r1"}
	}

	subset := tss.SortedPartyIDs{pIDs[0], pIDs[1]}
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*PresignParty, 2)
	for i, partyIdx := range []int{0, 1} {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[partyIdx], N, T)
		params.SetBroker(observers[partyIdx])
		pp, err := NewPresign(context.Background(), params, keys[partyIdx], subset)
		require.NoError(t, err)
		parties[i] = pp
	}

	for _, pp := range parties {
		select {
		case <-pp.Done:
		case err := <-pp.Err:
			t.Fatalf("presign failed: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatalf("presign timeout")
		}
	}

	for _, partyIdx := range []int{0, 1} {
		require.Equalf(t, 1, observers[partyIdx].bcastCount,
			"party %d should have sent exactly 1 broadcast for presign r1", partyIdx)
		require.Equalf(t, 0, observers[partyIdx].unicastCount,
			"party %d should not have sent any presign r1 unicasts", partyIdx)
	}
}
