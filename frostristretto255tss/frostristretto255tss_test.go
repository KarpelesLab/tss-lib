package frostristretto255tss

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// hubBroker, testHub, resharingHub mirror frosttss's test harness exactly.
// Copied verbatim to keep this package self-contained.

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
		if msg.To != nil {
			return b.hub.brokers[msg.To.Index].Receive(msg)
		}
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

func TestKeygenFull(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		keygens[i] = kg
	}
	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
		case err := <-keygens[i].Err:
			t.Fatalf("party %d keygen error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("party %d keygen timed out", i)
		}
	}
	for i := 1; i < partyCount; i++ {
		assert.True(t, keys[0].GroupPublicKey.Equal(keys[i].GroupPublicKey),
			"party 0 and %d should share GroupPublicKey", i)
	}
	for i := 1; i < partyCount; i++ {
		for j := range keys[0].BigXj {
			assert.True(t, keys[0].BigXj[j].Equal(keys[i].BigXj[j]),
				"BigXj[%d] mismatch between party 0 and %d", j, i)
		}
	}
}

func TestKeygenAndSign(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		keygens[i] = kg
	}
	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
		case err := <-keygens[i].Err:
			t.Fatalf("keygen error %d: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("keygen timeout %d", i)
		}
	}

	msg := []byte("FROST(ristretto255) hello")
	signHub := newTestHub(partyCount)
	signings := make([]*Signing, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(signHub.brokers[i])
		sg, err := keys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err)
		signings[i] = sg
	}
	sigs := make([]*SignatureData, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case sig := <-signings[i].Done:
			sigs[i] = sig
		case err := <-signings[i].Err:
			t.Fatalf("party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("party %d signing timeout", i)
		}
	}
	for i := 1; i < partyCount; i++ {
		assert.Equal(t, sigs[0].Signature, sigs[i].Signature, "signatures differ")
	}
	require.Len(t, sigs[0].Signature, 64)

	// Verify via the package-level verifier.
	ok, err := VerifySignature(keys[0].GroupPublicKey, msg, sigs[0].Signature)
	require.NoError(t, err)
	assert.True(t, ok, "FROST(ristretto255) signature must verify")
	t.Logf("signature: %x", sigs[0].Signature)
}

func TestKeygenAndSignStrictSubset(t *testing.T) {
	const (
		partyCount = 5
		threshold  = 2
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		keygens[i] = kg
	}
	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
		case err := <-keygens[i].Err:
			t.Fatalf("keygen error %d: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("keygen timeout %d", i)
		}
	}

	selected := []int{0, 2, 4}
	var unsorted tss.UnSortedPartyIDs
	for _, k := range selected {
		orig := pIDs[k]
		unsorted = append(unsorted, tss.NewPartyID(orig.Id, orig.Moniker, orig.KeyInt()))
	}
	subset := tss.SortPartyIDs(unsorted)
	require.Equal(t, 3, len(subset))
	for i := range subset {
		require.Equal(t, i, subset[i].Index)
	}

	subsetKeys := make([]*Key, len(subset))
	for i, subPID := range subset {
		for k, origPID := range pIDs {
			if bytes.Equal(origPID.Key, subPID.Key) {
				subsetKeys[i] = keys[k]
				break
			}
		}
		require.NotNil(t, subsetKeys[i])
	}

	msg := []byte("subset signing under FROST(ristretto255)")
	subsetCtx := tss.NewPeerContext(subset)
	signHub := newTestHub(len(subset))
	signings := make([]*Signing, len(subset))
	for i := 0; i < len(subset); i++ {
		params := tss.NewParameters(tss.Edwards(), subsetCtx, subset[i], len(subset), threshold)
		params.SetBroker(signHub.brokers[i])
		sg, err := subsetKeys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err)
		signings[i] = sg
	}
	sigs := make([]*SignatureData, len(subset))
	for i := 0; i < len(subset); i++ {
		select {
		case sig := <-signings[i].Done:
			sigs[i] = sig
		case err := <-signings[i].Err:
			t.Fatalf("subset party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("subset party %d signing timeout", i)
		}
	}
	for i := 1; i < len(subset); i++ {
		assert.Equal(t, sigs[0].Signature, sigs[i].Signature)
	}
	ok, err := VerifySignature(keys[0].GroupPublicKey, msg, sigs[0].Signature)
	require.NoError(t, err)
	assert.True(t, ok, "subset signature must verify under master pubkey")
}

// resharingHub mirrors frosttss's: routes by PartyID key (committees have
// independent index spaces).
type resharingHub struct {
	brokers map[string]*resharingBroker
}

type resharingBroker struct {
	partyKey string
	hub      *resharingHub
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage
	mu       sync.Mutex
}

func newResharingHub() *resharingHub {
	return &resharingHub{brokers: make(map[string]*resharingBroker)}
}
func (h *resharingHub) addParty(partyID *tss.PartyID) *resharingBroker {
	k := partyID.KeyInt().String()
	if b, ok := h.brokers[k]; ok {
		return b
	}
	b := &resharingBroker{
		partyKey: k,
		hub:      h,
		handlers: make(map[string]tss.MessageReceiver),
		pending:  make(map[string][]*tss.JsonMessage),
	}
	h.brokers[k] = b
	return b
}
func (b *resharingBroker) Connect(typ string, dest tss.MessageReceiver) {
	b.mu.Lock()
	b.handlers[typ] = dest
	q := b.pending[typ]
	delete(b.pending, typ)
	b.mu.Unlock()
	for _, msg := range q {
		_ = dest.Receive(msg)
	}
}
func (b *resharingBroker) Receive(msg *tss.JsonMessage) error {
	from := msg.From.KeyInt().String()
	if from == b.partyKey {
		if msg.To != nil {
			dest, ok := b.hub.brokers[msg.To.KeyInt().String()]
			if !ok {
				return fmt.Errorf("no broker for %s", msg.To.KeyInt())
			}
			return dest.Receive(msg)
		}
		for k, dest := range b.hub.brokers {
			if k == b.partyKey {
				continue
			}
			if err := dest.Receive(msg); err != nil {
				return err
			}
		}
		return nil
	}
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

func TestResharing(t *testing.T) {
	const (
		oldPartyCount = 3
		oldThreshold  = 1
		newPartyCount = 5
		newThreshold  = 2
	)

	oldPIDs := tss.GenerateTestPartyIDs(oldPartyCount)
	kgHub := newTestHub(oldPartyCount)
	oldP2P := tss.NewPeerContext(oldPIDs)

	keygens := make([]*Keygen, oldPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), oldP2P, oldPIDs[i], oldPartyCount, oldThreshold)
		params.SetBroker(kgHub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		keygens[i] = kg
	}
	oldKeys := make([]*Key, oldPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			oldKeys[i] = k
		case err := <-keygens[i].Err:
			t.Fatalf("keygen error %d: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("keygen timeout %d", i)
		}
	}
	originalPub := oldKeys[0].GroupPublicKey

	newPIDs := tss.GenerateTestPartyIDs(newPartyCount)
	newP2P := tss.NewPeerContext(newPIDs)
	rsHub := newResharingHub()
	oldBrokers := make([]*resharingBroker, oldPartyCount)
	for i, pid := range oldPIDs {
		oldBrokers[i] = rsHub.addParty(pid)
	}
	newBrokers := make([]*resharingBroker, newPartyCount)
	for i, pid := range newPIDs {
		newBrokers[i] = rsHub.addParty(pid)
	}

	total := oldPartyCount + newPartyCount
	resharings := make([]*Resharing, total)
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P, oldPIDs[i],
			oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetBroker(oldBrokers[i])
		rs, err := NewResharing(context.Background(), params, oldKeys[i])
		require.NoError(t, err)
		resharings[i] = rs
	}
	for i := 0; i < newPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P, newPIDs[i],
			oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetBroker(newBrokers[i])
		rs, err := NewResharing(context.Background(), params, nil)
		require.NoError(t, err)
		resharings[oldPartyCount+i] = rs
	}

	newKeys := make([]*Key, newPartyCount)
	for i := 0; i < total; i++ {
		select {
		case k := <-resharings[i].Done:
			if i < oldPartyCount {
				assert.Nil(t, k, "old party %d should receive nil key", i)
			} else {
				require.NotNil(t, k)
				newKeys[i-oldPartyCount] = k
			}
		case err := <-resharings[i].Err:
			t.Fatalf("resharing error party %d: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("resharing timeout party %d", i)
		}
	}
	for i := 0; i < newPartyCount; i++ {
		require.True(t, originalPub.Equal(newKeys[i].GroupPublicKey),
			"new party %d must preserve master GroupPublicKey", i)
	}

	msg := []byte("post-resharing FROST(ristretto255) signature")
	signHub := newTestHub(newPartyCount)
	signings := make([]*Signing, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		signCtx := tss.NewPeerContext(newPIDs)
		params := tss.NewParameters(tss.Edwards(), signCtx, newPIDs[i], newPartyCount, newThreshold)
		params.SetBroker(signHub.brokers[i])
		sg, err := newKeys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err)
		signings[i] = sg
	}
	sigs := make([]*SignatureData, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		select {
		case sig := <-signings[i].Done:
			sigs[i] = sig
		case err := <-signings[i].Err:
			t.Fatalf("new party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("new party %d signing timeout", i)
		}
	}
	for i := 1; i < newPartyCount; i++ {
		assert.Equal(t, sigs[0].Signature, sigs[i].Signature)
	}
	require.Len(t, sigs[0].Signature, 64)
	ok, err := VerifySignature(originalPub, msg, sigs[0].Signature)
	require.NoError(t, err)
	assert.True(t, ok, "post-resharing FROST(ristretto255) signature must verify")
}
