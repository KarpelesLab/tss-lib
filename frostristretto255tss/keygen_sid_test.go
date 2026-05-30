// Copyright © 2026 KarpelesLab.

package frostristretto255tss

import (
	"bytes"
	"context"
	"crypto/rand"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestBuildKeygenSessionDiffersOnNonce locks in the unit-level invariant that
// the per-PoK Session string includes the nonce, so two nonces over the same
// party key produce different session bytes (FIX 3).
func TestBuildKeygenSessionDiffersOnNonce(t *testing.T) {
	pk := big.NewInt(7)
	s1 := buildKeygenSession(pk, []byte("nonce-one-1234567"))
	s2 := buildKeygenSession(pk, []byte("nonce-two-1234567"))
	require.NotEqual(t, s1, s2, "Session bytes must differ when nonce differs")
}

// TestBuildKeygenSessionDiffersOnParty: two parties with different keys produce
// different session bytes (cross-party PoK substitution defense).
func TestBuildKeygenSessionDiffersOnParty(t *testing.T) {
	nonce := []byte("same-nonce-12345")
	s1 := buildKeygenSession(big.NewInt(1), nonce)
	s2 := buildKeygenSession(big.NewInt(2), nonce)
	require.NotEqual(t, s1, s2, "Session bytes must differ when partyKey differs")
}

// TestBuildKeygenSessionLengthPrefixUnambiguous: a length-prefix between
// partyKey and nonce makes the pair (partyKey, nonce) injectively encoded.
func TestBuildKeygenSessionLengthPrefixUnambiguous(t *testing.T) {
	pk1 := big.NewInt(0xAB)
	pk2 := new(big.Int).SetBytes([]byte{0xAB, 0xCD})
	nonce1 := []byte{0xCD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	nonce2 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	s1 := buildKeygenSession(pk1, nonce1)
	s2 := buildKeygenSession(pk2, nonce2)
	require.NotEqual(t, s1, s2, "length prefix must make encoding unambiguous")
}

// TestKeygenPoKReplayAcrossRunsRejected proves the core FIX 3 property: a
// Schnorr PoK produced under one keygen run's session nonce does NOT verify
// under a different run's session nonce. Because the verifier folds the
// broadcast nonce into the challenge, an attacker replaying an old PoK on the
// same phi_{i,0} but in a context expecting a fresh nonce is rejected.
func TestKeygenPoKReplayAcrossRunsRejected(t *testing.T) {
	g := group.Ristretto255()
	partyKey := big.NewInt(3)

	// Dealer's secret coefficient and its commitment phi_0 = x*G.
	x := g.RandomScalar(rand.Reader)
	phi0 := g.ScalarBaseMult(x)

	// Run A: prove under nonce A.
	nonceA := make([]byte, keygenSessionNonceLen)
	_, _ = rand.Read(nonceA)
	sessionA := buildKeygenSession(partyKey, nonceA)
	pok, err := schnorrProve(g, sessionA, x, phi0, rand.Reader)
	require.NoError(t, err)

	// Verifying under run A's nonce succeeds (sanity).
	require.True(t, schnorrVerify(g, sessionA, phi0, pok),
		"PoK must verify under its own run's session nonce")

	// Run B: a fresh nonce. Replaying run A's PoK against run B's challenge
	// must fail.
	nonceB := make([]byte, keygenSessionNonceLen)
	_, _ = rand.Read(nonceB)
	require.False(t, bytes.Equal(nonceA, nonceB))
	sessionB := buildKeygenSession(partyKey, nonceB)
	require.False(t, schnorrVerify(g, sessionB, phi0, pok),
		"replayed PoK must NOT verify under a different run's session nonce")
}

// roundOneTapBroker captures the FIRST round-1 broadcast from its party.
type roundOneTapBroker struct {
	*hubBroker
	captured chan *keygenRound1msg
	once     sync.Once
}

func (b *roundOneTapBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.Index == b.partyIdx && msg.Type == "frost:ristretto255:keygen:round1" {
		r1, err := tss.JsonGet[keygenRound1msg](msg)
		if err == nil {
			b.once.Do(func() { b.captured <- r1 })
		}
	}
	return b.hubBroker.Receive(msg)
}

// TestKeygenSessionNonceFreshPerRun is the end-to-end test that two keygen runs
// over the same party set produce different SessionNonce bytes for party 0 —
// i.e., the nonce is freshly sampled per call (FIX 3).
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
		"SessionNonce must be freshly sampled per keygen run")
}
