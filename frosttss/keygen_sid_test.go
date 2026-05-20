// Copyright © 2026 KarpelesLab.

package frosttss

import (
	"bytes"
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestBuildKeygenSessionDiffersOnNonce locks in the unit-level invariant
// that the per-PoK Session string includes the nonce, so two nonces over
// the same party key produce different session bytes.
func TestBuildKeygenSessionDiffersOnNonce(t *testing.T) {
	pk := big.NewInt(7)
	s1 := buildKeygenSession(pk, []byte("nonce-one-1234567"))
	s2 := buildKeygenSession(pk, []byte("nonce-two-1234567"))
	require.NotEqual(t, s1, s2, "Session bytes must differ when nonce differs")
}

// TestBuildKeygenSessionDiffersOnParty: two parties with different keys
// produce different session bytes (cross-party PoK substitution defense).
func TestBuildKeygenSessionDiffersOnParty(t *testing.T) {
	nonce := []byte("same-nonce-12345")
	s1 := buildKeygenSession(big.NewInt(1), nonce)
	s2 := buildKeygenSession(big.NewInt(2), nonce)
	require.NotEqual(t, s1, s2, "Session bytes must differ when partyKey differs")
}

// TestBuildKeygenSessionLengthPrefixUnambiguous: a length-prefix between
// partyKey and nonce makes the pair (partyKey, nonce) injectively
// encoded. Two distinct pairs whose concatenation could otherwise be
// ambiguous (e.g., partyKey={0xAB}, nonce={0xCD,...} vs partyKey={0xAB,0xCD},
// nonce={...}) must produce different session bytes.
func TestBuildKeygenSessionLengthPrefixUnambiguous(t *testing.T) {
	pk1 := big.NewInt(0xAB) // 1-byte bytes
	pk2 := new(big.Int).SetBytes([]byte{0xAB, 0xCD})
	nonce1 := []byte{0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	nonce2 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	s1 := buildKeygenSession(pk1, nonce1)
	s2 := buildKeygenSession(pk2, nonce2)
	require.NotEqual(t, s1, s2, "length prefix must make encoding unambiguous")
}

// roundOneTapBroker wraps a hubBroker and captures the FIRST outbound
// round-1 broadcast it observes, for use in tests that need to inspect
// the wire-level SessionNonce.
type roundOneTapBroker struct {
	*hubBroker
	captured chan *keygenRound1msg
	once     sync.Once
}

func (b *roundOneTapBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.Index == b.partyIdx && msg.Type == "frost:ed25519:keygen:round1" {
		r1, err := tss.JsonGet[keygenRound1msg](msg)
		if err == nil {
			b.once.Do(func() {
				b.captured <- r1
			})
		}
	}
	return b.hubBroker.Receive(msg)
}

// TestKeygenSessionNonceFreshPerRun is the end-to-end test that two
// keygen runs over the same party set produce different SessionNonce
// bytes for party 0 — i.e., the nonce is freshly sampled per call.
func TestKeygenSessionNonceFreshPerRun(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)

	runKeygenCaptureR1 := func() *keygenRound1msg {
		pIDs := tss.GenerateTestPartyIDs(partyCount)
		hub := newTestHub(partyCount)
		p2pCtx := tss.NewPeerContext(pIDs)

		tap := &roundOneTapBroker{
			hubBroker: hub.brokers[0],
			captured:  make(chan *keygenRound1msg, 1),
		}

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

		// Wait for DKG to either succeed or fail.
		for i := 0; i < partyCount; i++ {
			select {
			case <-keygens[i].Done:
			case err := <-keygens[i].Err:
				t.Fatalf("party %d keygen error: %v", i, err)
			case <-time.After(2 * time.Minute):
				t.Fatalf("party %d keygen timed out", i)
			}
		}

		select {
		case r1 := <-tap.captured:
			return r1
		case <-time.After(time.Second):
			t.Fatal("did not capture round-1 broadcast from party 0")
			return nil
		}
	}

	r1a := runKeygenCaptureR1()
	r1b := runKeygenCaptureR1()
	require.Equal(t, keygenSessionNonceLen, len(r1a.SessionNonce))
	require.Equal(t, keygenSessionNonceLen, len(r1b.SessionNonce))
	require.False(t, bytes.Equal(r1a.SessionNonce, r1b.SessionNonce),
		"SessionNonce must be freshly sampled per keygen run (got the same %d bytes twice)",
		keygenSessionNonceLen)
}
