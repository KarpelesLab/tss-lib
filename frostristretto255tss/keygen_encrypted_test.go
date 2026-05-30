// Copyright © 2026 KarpelesLab.

package frostristretto255tss

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// roundTwoTapBroker wraps a hubBroker and captures every outbound round-2
// message from its party, exposing them for inspection.
type roundTwoTapBroker struct {
	*hubBroker
	mu       sync.Mutex
	captured []*tss.JsonMessage
}

func (b *roundTwoTapBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.Index == b.partyIdx && msg.Type == "frost:ristretto255:keygen:round2" {
		b.mu.Lock()
		b.captured = append(b.captured, &tss.JsonMessage{
			Type: msg.Type, From: msg.From, To: msg.To, Data: msg.Data,
		})
		b.mu.Unlock()
	}
	return b.hubBroker.Receive(msg)
}

// TestKeygenRound2SharesAreEncrypted is the headline test for the
// encrypted-shares hardening (FIX 1): a passive eavesdropper on the broker
// transport cannot recover the plaintext share even with full knowledge of
// every round-1 broadcast. The wire-level round-2 payload must contain only a
// ciphertext and the secret share scalar must NOT appear in the bytes.
func TestKeygenRound2SharesAreEncrypted(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	tap := &roundTwoTapBroker{hubBroker: hub.brokers[0]}

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		if i == 0 {
			params.SetBroker(tap)
		} else {
			params.SetBroker(hub.brokers[i])
		}
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
		case <-time.After(2 * time.Minute):
			t.Fatalf("party %d keygen timed out", i)
		}
	}

	tap.mu.Lock()
	captured := append([]*tss.JsonMessage(nil), tap.captured...)
	tap.mu.Unlock()
	require.NotEmpty(t, captured, "tap broker should have captured round-2 outbound messages")

	for _, m := range captured {
		r2, err := tss.JsonGet[keygenRound2msg](m)
		require.NoError(t, err)
		require.NotEmpty(t, r2.Ciphertext, "round-2 payload must carry a Ciphertext")
		require.Greater(t, len(r2.Ciphertext), 28,
			"ciphertext must be at least nonce(12) + tag(16) bytes long; got %d", len(r2.Ciphertext))
	}

	// The plaintext share scalars party 0 emitted must not be observable on the
	// wire. We don't have party 0's plaintext shares here, but every other
	// party's final Xi is a sum that includes party 0's share to it; as a
	// sanity check ensure no party's Xi bytes appear verbatim in any ciphertext.
	for _, k := range keys {
		if k.Xi == nil {
			continue
		}
		xiBytes := k.Xi.Bytes()
		if len(xiBytes) == 0 {
			continue
		}
		for _, m := range captured {
			r2, err := tss.JsonGet[keygenRound2msg](m)
			require.NoError(t, err)
			require.False(t,
				bytes.Contains(r2.Ciphertext, xiBytes),
				"final Xi appears verbatim in ciphertext (encryption broken)")
		}
	}
}

// round2TamperingBroker wraps a hubBroker and flips one byte of the FIRST
// round-2 unicast message it observes, then forwards to the hub.
type round2TamperingBroker struct {
	*hubBroker
	mu      sync.Mutex
	flipped bool
}

func (b *round2TamperingBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.Index == b.partyIdx && msg.Type == "frost:ristretto255:keygen:round2" {
		b.mu.Lock()
		if !b.flipped {
			b.flipped = true
			b.mu.Unlock()
			r2, err := tss.JsonGet[keygenRound2msg](msg)
			if err == nil && len(r2.Ciphertext) > 0 {
				r2.Ciphertext[len(r2.Ciphertext)-1] ^= 0x01
				msg.Data = r2
			}
		} else {
			b.mu.Unlock()
		}
	}
	return b.hubBroker.Receive(msg)
}

// TestKeygenRound2CiphertextTamperingDetected: flipping any byte of a captured
// round-2 ciphertext must cause the recipient's AEAD open to fail
// (ChaCha20-Poly1305 integrity tag), surfacing as a keygen error.
func TestKeygenRound2CiphertextTamperingDetected(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	tamper := &round2TamperingBroker{hubBroker: hub.brokers[0]}

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		if i == 0 {
			params.SetBroker(tamper)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		keygens[i] = kg
	}

	sawOpenFailure := false
	doneCount := 0
	deadline := time.After(2 * time.Minute)
	for !sawOpenFailure && doneCount < partyCount {
		for i := 0; i < partyCount; i++ {
			select {
			case <-keygens[i].Done:
				doneCount++
			case e := <-keygens[i].Err:
				if e != nil {
					sawOpenFailure = true
				}
				doneCount++
			case <-deadline:
				t.Fatalf("deadline exceeded; doneCount=%d", doneCount)
			default:
				continue
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, sawOpenFailure, "at least one recipient must error on tampered ciphertext")
}

// TestKeygenRound2FieldNameIsCiphertext locks in the wire-format rename:
// round-2 must carry a Ciphertext field, not a Share field.
func TestKeygenRound2FieldNameIsCiphertext(t *testing.T) {
	r2 := &keygenRound2msg{Ciphertext: []byte("dummy")}
	b, err := json.Marshal(r2)
	require.NoError(t, err)
	require.Contains(t, string(b), "\"ciphertext\"")
	require.NotContains(t, string(b), "\"share\"")
}
