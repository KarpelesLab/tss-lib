package dklstss

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// hubBroker is a test-only broker that simulates network routing
// in-process. Each party has its own *hubBroker. Outbound messages
// (msg.From.Index == this party's index) are routed to the
// destination's broker; inbound messages are dispatched to the
// registered handler or buffered until one is registered.
type hubBroker struct {
	partyIdx int
	hub      *testHub
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage
	mu       sync.Mutex
}

type testHub struct {
	brokers []*hubBroker
}

func newTestHub(n int) *testHub {
	h := &testHub{brokers: make([]*hubBroker, n)}
	for i := 0; i < n; i++ {
		h.brokers[i] = &hubBroker{
			partyIdx: i,
			hub:      h,
			handlers: make(map[string]tss.MessageReceiver),
			pending:  make(map[string][]*tss.JsonMessage),
		}
	}
	return h
}

func (b *hubBroker) Connect(typ string, dest tss.MessageReceiver) {
	b.mu.Lock()
	b.handlers[typ] = dest
	queued := b.pending[typ]
	delete(b.pending, typ)
	b.mu.Unlock()
	for _, msg := range queued {
		if err := dest.Receive(msg); err != nil {
			fmt.Printf("hubBroker: deliver queued %s to party %d: %v\n", typ, b.partyIdx, err)
		}
	}
}

func (b *hubBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.Index == b.partyIdx {
		// Outbound; route to destination's broker.
		if msg.To != nil {
			return b.hub.brokers[msg.To.Index].Receive(msg)
		}
		// Broadcast.
		for j, broker := range b.hub.brokers {
			if j == b.partyIdx {
				continue
			}
			if err := broker.Receive(msg); err != nil {
				return err
			}
		}
		return nil
	}
	// Inbound to this party.
	b.mu.Lock()
	handler, ok := b.handlers[msg.Type]
	if !ok {
		b.pending[msg.Type] = append(b.pending[msg.Type], msg)
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()
	return handler.Receive(msg)
}

// TestKeygenPartyEndToEnd runs N KeygenParty instances in parallel
// (each as a separate goroutine pretending to be a different node),
// connected via the in-process hubBroker. Verifies they all complete
// with consistent keys that produce a verifying signature.
func TestKeygenPartyEndToEnd(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*KeygenParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		parties[i] = kg
	}

	keys := make([]*Key, partyCount)
	for i, p := range parties {
		select {
		case k := <-p.Done:
			keys[i] = k
		case err := <-p.Err:
			t.Fatalf("party %d failed: %v", i, err)
		case <-time.After(60 * time.Second):
			t.Fatalf("party %d timed out", i)
		}
	}

	// All parties agree on the joint public key.
	pub := keys[0].ECDSAPub
	for i := 1; i < partyCount; i++ {
		assert.True(t, keys[i].ECDSAPub.Equals(pub), "party %d has different public key", i)
	}

	// Each party can now sign (via the synchronous API) and the
	// signature verifies under the joint public key.
	msg := sha256.Sum256([]byte("party-keygen end-to-end"))
	sig, err := Sign(keys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	pubECDSA := &ecdsa.PublicKey{Curve: pub.Curve(), X: pub.X(), Y: pub.Y()}
	assert.True(t, ecdsa.Verify(pubECDSA, msg[:], sig.R, sig.S))
}

// TestKeygenPartyMatchesSyncKeygen sanity-checks that the broker-driven
// Party produces keys with the same structure (same N, T, same threshold
// semantics) as the synchronous Keygen function.
func TestKeygenPartyMatchesSyncKeygen(t *testing.T) {
	const partyCount, threshold = 2, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*KeygenParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		parties[i] = kg
	}

	keys := make([]*Key, partyCount)
	for i, p := range parties {
		select {
		case k := <-p.Done:
			keys[i] = k
		case err := <-p.Err:
			t.Fatalf("party %d failed: %v", i, err)
		case <-time.After(60 * time.Second):
			t.Fatalf("party %d timed out", i)
		}
	}

	for i, k := range keys {
		assert.Equal(t, partyCount, k.N, "key %d N", i)
		assert.Equal(t, threshold, k.T, "key %d T", i)
		assert.Equal(t, i, k.Idx, "key %d Idx", i)
		assert.NotNil(t, k.Xi)
		assert.NotNil(t, k.ECDSAPub)
		assert.Len(t, k.OT, partyCount)
	}
}
