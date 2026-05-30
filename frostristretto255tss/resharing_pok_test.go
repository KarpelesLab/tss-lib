// Copyright © 2026 KarpelesLab.

package frostristretto255tss

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// rsVi0TamperBroker rewrites the FIRST outbound round-1 reshare message it
// observes from its party by substituting a different Vi0. The Schnorr PoK on
// the original wi remains valid for the ORIGINAL Vi0 but not for the
// substituted value, so the receiver's round-2 verification must reject the
// dealer (identity check or PoK failure), naming it in Culprits().
type rsVi0TamperBroker struct {
	*resharingBroker
	newVi0   []byte
	tampered atomic.Bool
	mu       sync.Mutex
}

func (b *rsVi0TamperBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.KeyInt().String() == b.partyKey && msg.Type == "frost:ristretto255:reshare:round1" {
		if b.tampered.CompareAndSwap(false, true) {
			r1, err := tss.JsonGet[resharingRound1msg](msg)
			if err == nil {
				r1.Vi0 = b.newVi0
				msg.Data = r1
			}
		}
	}
	return b.resharingBroker.Receive(msg)
}

func runReshareWithTamper(t *testing.T, newVi0 []byte) {
	t.Helper()
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
	tamper := &rsVi0TamperBroker{resharingBroker: oldBrokers[0], newVi0: newVi0}

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

	tamperPID := oldPIDs[0]
	for i := 0; i < newPartyCount; i++ {
		idx := oldPartyCount + i
		select {
		case <-resharings[idx].Done:
			t.Fatalf("new party %d unexpectedly succeeded with tampered Vi0", i)
		case e := <-resharings[idx].Err:
			require.Error(t, e)
			tssErr, ok := e.(*tss.Error)
			require.Truef(t, ok, "new party %d error must be *tss.Error: %v", i, e)
			culprits := tssErr.Culprits()
			require.NotEmpty(t, culprits, "new party %d Culprits() must be populated", i)
			require.Equal(t, tamperPID.KeyInt().String(), culprits[0].KeyInt().String(),
				"new party %d Culprits() must name the tampered dealer", i)
			require.True(t,
				strings.Contains(e.Error(), "PoK") ||
					strings.Contains(e.Error(), "identity") ||
					strings.Contains(e.Error(), "equivocation"),
				"new party %d error should mention PoK / identity / equivocation: %v", i, e)
		case <-time.After(2 * time.Minute):
			t.Fatalf("new party %d did not error within timeout", i)
		}
	}
}

// TestResharingRejectsIdentityVi0 verifies the per-dealer integrity fix
// (FIX 2): an old dealer whose round-1 Vi0 is the group identity is rejected
// by every new-committee verifier during round-2 verification.
func TestResharingRejectsIdentityVi0(t *testing.T) {
	g := group.Ristretto255()
	runReshareWithTamper(t, g.Identity().Bytes())
}

// TestResharingRejectsSubstitutedVi0 verifies that substituting a different
// non-identity Vi0 (for which the dealer's PoK is invalid) is rejected: the
// PoK was bound to the original vi[0] = wi*G and does not verify against the
// substituted point.
func TestResharingRejectsSubstitutedVi0(t *testing.T) {
	g := group.Ristretto255()
	// A fixed non-identity element: the generator.
	runReshareWithTamper(t, g.Generator().Bytes())
}
