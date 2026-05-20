// Copyright © 2026 KarpelesLab.

package dklstss

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// echoOmittingBroker wraps a hubBroker; when the wrapped party (the
// echoer) emits a To==nil echo broadcast, the broker deletes one
// specific dealer's digest entry from the map before forwarding. This
// simulates the "omitted-dealer" equivocation cover-up: a malicious
// dealer + a colluding echoer can equivocate against a non-colluding
// peer who never receives a contradicting echo.
//
// Without the coverage check, the protocol completes despite the
// equivocation. With the coverage check, the non-colluding peer
// rejects the echoer's broadcast as a protocol violation.
type echoOmittingBroker struct {
	*hubBroker
	omitDealerKey string // PartyID.KeyInt().String() of the dealer to drop
	flipped       atomic.Bool
}

func (b *echoOmittingBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From != nil && msg.From.Index == b.partyIdx && msg.Type == keygenTypeEcho {
		if b.flipped.CompareAndSwap(false, true) {
			ec, err := tss.JsonGet[echoMsg](msg)
			if err == nil && ec.Digests != nil {
				delete(ec.Digests, b.omitDealerKey)
				msg.Data = ec
			}
		}
	}
	return b.hubBroker.Receive(msg)
}

// TestEchoCoverageRejectsOmittedDealer is the regression test for the
// audit's HIGH-4 finding: a malicious echoer who omits a dealer's
// digest must be rejected by every non-colluding recipient, with the
// echoer in Culprits().
func TestEchoCoverageRejectsOmittedDealer(t *testing.T) {
	const partyCount, threshold = 4, 2
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)

	// Party 1 (echoer) drops the digest entry for party 0 (dealer)
	// from its echo broadcast. Party 0 IS in the dealer set; its
	// commitments are real. Without the coverage check, party 1's
	// omission would let a colluding party 0 equivocate to other
	// peers undetected.
	tamper := &echoOmittingBroker{
		hubBroker:     hub.brokers[1],
		omitDealerKey: pIDs[0].KeyInt().String(),
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*KeygenParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		if i == 1 {
			params.SetBroker(tamper)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		kp, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		parties[i] = kp
	}

	// At least one party (not the tamperer) must error out with party 1
	// in Culprits() — the omission attribution.
	tamperPID := pIDs[1]
	sawAttribution := false
	deadline := time.After(2 * time.Minute)
	for i := 0; i < partyCount; i++ {
		if i == 1 {
			continue // skip the tamperer's own outcome
		}
		select {
		case <-parties[i].Done:
		case e := <-parties[i].Err:
			require.Error(t, e)
			tssErr, ok := e.(*tss.Error)
			if !ok {
				continue
			}
			for _, c := range tssErr.Culprits() {
				if c.KeyInt().Cmp(tamperPID.KeyInt()) == 0 {
					sawAttribution = true
					require.True(t,
						strings.Contains(e.Error(), "omitted") || strings.Contains(e.Error(), "omit"),
						"error from party %d should mention omission: %v", i, e)
				}
			}
		case <-deadline:
			t.Fatalf("party %d did not finish within deadline", i)
		}
	}
	require.True(t, sawAttribution, "at least one party must attribute the omission to the tamperer (party 1)")
}

// TestEchoCoverageRejectsSelfEntry verifies the MEDIUM fix: if an
// echoer mistakenly (or maliciously) ships its own digest under its
// own key, the protocol must reject with the echoer in Culprits()
// instead of returning a generic fmt.Errorf.
type echoSelfEntryBroker struct {
	*hubBroker
	flipped atomic.Bool
}

func (b *echoSelfEntryBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From != nil && msg.From.Index == b.partyIdx && msg.Type == keygenTypeEcho {
		if b.flipped.CompareAndSwap(false, true) {
			ec, err := tss.JsonGet[echoMsg](msg)
			if err == nil && ec.Digests != nil {
				// Inject a self-entry: echoer reports a digest under
				// its own KeyInt.
				ec.Digests[msg.From.KeyInt().String()] = []byte("dummy-self-digest")
				msg.Data = ec
			}
		}
	}
	return b.hubBroker.Receive(msg)
}

func TestEchoCoverageRejectsSelfEntry(t *testing.T) {
	const partyCount, threshold = 4, 2
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)

	tamper := &echoSelfEntryBroker{hubBroker: hub.brokers[2]}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*KeygenParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		if i == 2 {
			params.SetBroker(tamper)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		kp, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		parties[i] = kp
	}

	tamperPID := pIDs[2]
	sawAttribution := false
	deadline := time.After(2 * time.Minute)
	for i := 0; i < partyCount; i++ {
		if i == 2 {
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
				}
			}
		case <-deadline:
			t.Fatalf("party %d deadline", i)
		}
	}
	require.True(t, sawAttribution, "self-entry must surface as identifiable abort against the echoer")
}
