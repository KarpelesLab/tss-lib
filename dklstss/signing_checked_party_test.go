// Copyright © 2026 KarpelesLab.

package dklstss

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestCheckedSigningPartyHappyPath verifies the broker-driven Mul-then-
// check path produces a valid ECDSA signature when all parties behave.
// Locks in the basic correctness invariant for CheckedSigningParty.
func TestCheckedSigningPartyHappyPath(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)

	subset := pIDs[:threshold+1]
	signCtx := tss.NewPeerContext(subset)
	hub := newTestHub(threshold + 1)

	msg := sha256.Sum256([]byte("checked-sign-broker"))

	parties := make([]*CheckedSigningParty, threshold+1)
	for i := 0; i < threshold+1; i++ {
		params := tss.NewParameters(tss.S256(), signCtx, subset[i], threshold+1, threshold)
		params.SetBroker(hub.brokers[i])
		sIdx := -1
		for n, p := range pIDs {
			if p.KeyInt().Cmp(subset[i].KeyInt()) == 0 {
				sIdx = n
				break
			}
		}
		require.GreaterOrEqual(t, sIdx, 0)
		sp, err := NewCheckedSigning(context.Background(), params, keys[sIdx], msg[:], subset, nil)
		require.NoError(t, err)
		parties[i] = sp
	}

	var sig *Signature
	deadline := time.After(2 * time.Minute)
	for i := 0; i < threshold+1; i++ {
		select {
		case s := <-parties[i].Done:
			require.NotNil(t, s)
			if i == 0 {
				sig = s
			} else {
				require.Equal(t, 0, sig.R.Cmp(s.R))
				require.Equal(t, 0, sig.S.Cmp(s.S))
			}
		case e := <-parties[i].Err:
			t.Fatalf("party %d error: %v", i, e)
		case <-deadline:
			t.Fatalf("party %d timed out", i)
		}
	}

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	require.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// betaTamperingBroker rewrites the FIRST CheckedR3 message it observes
// from the wrapped Bob (sender) so that BobK2 differs from BobK1 in a
// way the receiving Alice's CheckedAliceStep2 will reject (Z_A + Z_B != 0).
// This simulates "Bob used inconsistent β across the two parallel ΠMul runs."
type betaTamperingBroker struct {
	*hubBroker
	flipped atomic.Bool
}

func (b *betaTamperingBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From != nil && msg.From.Index == b.partyIdx && msg.Type == checkedSignTypeR3 {
		if b.flipped.CompareAndSwap(false, true) {
			r3, err := tss.JsonGet[checkedSignR3](msg)
			if err == nil && r3.BobKZ != nil {
				// Flip the lowest bit of Bob's Z value. Since Z =
				// u_B1 − u_B2 mod q encodes Bob's consistency claim,
				// a single-bit flip yields Z' ≠ Z, so Z_A + Z' ≠ 0
				// (since the honest equation had Z_A + Z == 0). The
				// receiving Alice's CheckedAliceStep2 will return
				// ErrMulCheckFailed and round4 attributes the
				// failure to this Bob.
				z := append([]byte(nil), r3.BobKZ...)
				if len(z) > 0 {
					z[len(z)-1] ^= 0x01
				}
				r3.BobKZ = z
				msg.Data = r3
			}
		}
	}
	return b.hubBroker.Receive(msg)
}

// TestCheckedSigningCatchesBetaInconsistency is the headline regression
// for the Mul-then-check defense: a malicious peer who corrupts their
// Z value (simulating "used different β across the two parallel ΠMul
// runs") surfaces with identifiable abort, naming the corrupted party
// in Culprits().
func TestCheckedSigningCatchesBetaInconsistency(t *testing.T) {
	const partyCount, threshold = 4, 2
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)

	subset := pIDs[:threshold+1]
	signCtx := tss.NewPeerContext(subset)
	hub := newTestHub(threshold + 1)
	tamper := &betaTamperingBroker{hubBroker: hub.brokers[0]}

	msg := sha256.Sum256([]byte("checked-beta-tampering"))
	parties := make([]*CheckedSigningParty, threshold+1)
	for i := 0; i < threshold+1; i++ {
		params := tss.NewParameters(tss.S256(), signCtx, subset[i], threshold+1, threshold)
		if i == 0 {
			params.SetBroker(tamper)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		sIdx := -1
		for n, p := range pIDs {
			if p.KeyInt().Cmp(subset[i].KeyInt()) == 0 {
				sIdx = n
				break
			}
		}
		require.GreaterOrEqual(t, sIdx, 0)
		sp, err := NewCheckedSigning(context.Background(), params, keys[sIdx], msg[:], subset, nil)
		require.NoError(t, err)
		parties[i] = sp
	}

	// At least one of the honest peers (party 1 or 2 — the Alices for
	// the tampered Bob=party-0) must surface tss.Error with party 0
	// in Culprits() and a message mentioning "Mul-then-check".
	tamperPID := subset[0]
	sawAttribution := false
	// Once any honest peer aborts with party 0 in Culprits, the
	// protocol can never complete (the other Alices stay waiting for
	// round-3 from party 0 to ALL recipients). Accept any one
	// successful attribution within the deadline.
	deadline := time.After(2 * time.Minute)
	for i := 0; i < threshold+1 && !sawAttribution; i++ {
		if i == 0 {
			continue
		}
		select {
		case <-parties[i].Done:
		case e := <-parties[i].Err:
			tssErr, ok := e.(*tss.Error)
			if !ok {
				continue
			}
			for _, c := range tssErr.Culprits() {
				if c.KeyInt().Cmp(tamperPID.KeyInt()) == 0 {
					sawAttribution = true
					t.Logf("party %d correctly attributed: %v", i, e)
				}
			}
		case <-deadline:
			break // other parties may still be running; check overall result
		}
	}
	require.True(t, sawAttribution,
		"CheckedSigningParty must attribute β-inconsistency to the tampered Bob (party 0)")
}

// Suppress unused-import warnings if other imports are pruned later.
var _ = big.NewInt
