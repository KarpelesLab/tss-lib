// Copyright © 2026 KarpelesLab.

package frosttss

import (
	"context"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// rsTamperBroker wraps a *resharingBroker and rewrites the FIRST outbound
// round-1 reshare message it observes by substituting a different Vi0
// (the curve identity). The Schnorr PoK on the original wi remains valid
// for the original Vi0 but NOT for the substituted identity, so the
// receiver's round-2 PoK verification must fail with the dealer in
// Culprits().
type rsTamperBroker struct {
	*resharingBroker
	tampered atomic.Bool
	mu       sync.Mutex
}

func (b *rsTamperBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.KeyInt().String() == b.partyKey && msg.Type == "frost:ed25519:reshare:round1" {
		if b.tampered.CompareAndSwap(false, true) {
			r1, err := tss.JsonGet[resharingRound1msg](msg)
			if err == nil {
				ec := edwards25519.Edwards()
				identity, err := crypto.NewECPoint(ec, big.NewInt(0), big.NewInt(1))
				if err == nil {
					r1.Vi0 = frost.EncodeElement(identity)
					msg.Data = r1
				}
			}
		}
	}
	return b.resharingBroker.Receive(msg)
}

// TestResharingRejectsIdentityVi0 verifies the audit fix HIGH-8: an
// old dealer that broadcasts Vi0 = identity in round 1 is rejected by
// every new-committee verifier during round-2 PoK verification.
func TestResharingRejectsIdentityVi0(t *testing.T) {
	const (
		oldPartyCount = 3
		oldThreshold  = 1
		newPartyCount = 5
		newThreshold  = 2
	)

	// Phase 1: keygen with old committee.
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
		case <-time.After(2 * time.Minute):
			t.Fatalf("keygen timeout %d", i)
		}
	}

	// Phase 2: reshare. Old party 0 uses a tampering broker.
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
	// Tamper broker for old party 0.
	tamper := &rsTamperBroker{resharingBroker: oldBrokers[0]}

	resharings := make([]*Resharing, 0, oldPartyCount+newPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P,
			oldPIDs[i], oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		if i == 0 {
			params.SetBroker(tamper)
		} else {
			params.SetBroker(oldBrokers[i])
		}
		rs, err := NewResharing(context.Background(), params, oldKeys[i])
		require.NoError(t, err)
		resharings = append(resharings, rs)
	}
	for i := 0; i < newPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P,
			newPIDs[i], oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetBroker(newBrokers[i])
		rs, err := NewResharing(context.Background(), params, nil)
		require.NoError(t, err)
		resharings = append(resharings, rs)
	}

	// Each new-committee party should error with the tampered dealer
	// (old party 0) in Culprits(). The old parties either succeed (they
	// did their job) or block waiting for ACKs that never arrive.
	tamperPID := oldPIDs[0]
	for i := 0; i < newPartyCount; i++ {
		idx := oldPartyCount + i
		select {
		case <-resharings[idx].Done:
			t.Fatalf("new party %d unexpectedly succeeded", i)
		case e := <-resharings[idx].Err:
			require.Error(t, e)
			tssErr, ok := e.(*tss.Error)
			require.Truef(t, ok, "new party %d error must be *tss.Error: %v", i, e)
			culprits := tssErr.Culprits()
			require.NotEmpty(t, culprits, "new party %d Culprits() must be populated", i)
			require.Equal(t, tamperPID.KeyInt().String(), culprits[0].KeyInt().String(),
				"new party %d Culprits() must name the tampered dealer", i)
			require.True(t,
				strings.Contains(e.Error(), "PoK") || strings.Contains(e.Error(), "identity"),
				"new party %d error should mention PoK or identity: %v", i, e)
		case <-time.After(2 * time.Minute):
			t.Fatalf("new party %d did not error within timeout", i)
		}
	}
}

// TestResharingScrubsXiOnSuccess verifies that the old committee's Xi
// is zeroized at the LIMB level after a successful reshare (audit
// finding: previous SetInt64(0) only zeroed Sign(), leaving the
// underlying big.Int backing array intact).
func TestResharingScrubsXiOnSuccess(t *testing.T) {
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
			t.Fatalf("keygen %d: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("keygen %d timed out", i)
		}
	}

	// Capture pre-reshare Xi's BACKING array so we can inspect the limbs
	// after zeroize. big.Int.Bits() returns a slice that aliases the
	// underlying word slice; SetInt64(0) shrinks the slice to length 0
	// but leaves the array contents. ZeroizeBigInt should wipe them.
	preBits := oldKeys[0].Xi.Bits()
	backing := preBits[:cap(preBits):cap(preBits)]
	require.NotEmpty(t, backing, "pre-reshare Xi backing must be non-empty")

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
	resharings := make([]*Resharing, 0, oldPartyCount+newPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P,
			oldPIDs[i], oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetBroker(oldBrokers[i])
		rs, err := NewResharing(context.Background(), params, oldKeys[i])
		require.NoError(t, err)
		resharings = append(resharings, rs)
	}
	for i := 0; i < newPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P,
			newPIDs[i], oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetBroker(newBrokers[i])
		rs, err := NewResharing(context.Background(), params, nil)
		require.NoError(t, err)
		resharings = append(resharings, rs)
	}

	for i, rs := range resharings {
		select {
		case <-rs.Done:
		case err := <-rs.Err:
			t.Fatalf("reshare party %d: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("reshare party %d timed out", i)
		}
	}

	// Inspect the captured backing array — every limb must be zero.
	require.Equal(t, 0, oldKeys[0].Xi.Sign(), "post-reshare Xi must be numerically zero")
	for i := 0; i < len(backing); i++ {
		require.Equal(t, uint(0), uint(backing[i]),
			"post-reshare Xi backing[%d] = %x, want 0 (ZeroizeBigInt should wipe limbs)", i, backing[i])
	}
}
