// Copyright © 2026 KarpelesLab.

package dklstss

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// freshSecp256k1Point returns a random non-identity secp256k1 point.
// Used to build a VALID-but-different K for equivocation testing —
// just flipping a byte of an existing KiX almost always lands off-
// curve, which the round-2 NewECPoint check catches before the echo
// phase. To exercise the echo phase specifically we need an alternate
// on-curve point.
func freshSecp256k1Point() ([]byte, []byte) {
	ec := tss.S256()
	k, err := rand.Int(rand.Reader, ec.Params().N)
	if err != nil {
		panic(err)
	}
	x, y := ec.ScalarBaseMult(k.Bytes())
	return x.Bytes(), y.Bytes()
}

// kEquivocatingBroker wraps a hubBroker and ships different (but
// on-curve) K_i bytes to different recipients under a single To==nil
// broadcast. Without the echo-phase fix this slides through into the
// ssid mix and surfaces only as an opaque ΠMul failure (no Culprits);
// with the echo fix the protocol aborts identifiably.
type kEquivocatingBroker struct {
	*hubBroker
	msgType string
	flipped atomic.Bool
}

func (b *kEquivocatingBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From != nil && msg.From.Index == b.partyIdx && msg.To == nil && msg.Type == b.msgType {
		if b.flipped.CompareAndSwap(false, true) {
			r1, err := tss.JsonGet[signR1](msg)
			if err != nil || len(r1.KiX) == 0 {
				return b.hubBroker.Receive(msg)
			}
			altX, altY := freshSecp256k1Point()
			altR1 := &signR1{KiX: altX, KiY: altY}
			for j, broker := range b.hub.brokers {
				if j == b.partyIdx {
					continue
				}
				mutated := *msg
				if j == 1 {
					mutated.Data = altR1
				} else {
					mutated.Data = r1
				}
				if err := broker.Receive(&mutated); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return b.hubBroker.Receive(msg)
}

// TestSigningEquivocationCaughtByEcho is the regression test for the
// audit's signing-equivocation finding: a malicious broker that ships
// different K_i bytes to different signers is caught with identifiable
// abort by the echo-broadcast phase, naming the equivocating party in
// Culprits().
func TestSigningEquivocationCaughtByEcho(t *testing.T) {
	const partyCount, threshold = 4, 2 // 3 signers, so echo phase can triangulate
	pIDs := tss.GenerateTestPartyIDs(partyCount)

	// Phase 1: keygen with normal brokers.
	keys := runDistributedKeygen(t, pIDs, threshold)

	// Phase 2: signing with an equivocating broker on party 0.
	signSubset := pIDs[:threshold+1] // 2 signers
	hub := newTestHub(threshold + 1)
	tamper := &kEquivocatingBroker{hubBroker: hub.brokers[0], msgType: signTypeR1}

	signCtx := tss.NewPeerContext(signSubset)
	signings := make([]*SigningParty, threshold+1)
	msgHash := make([]byte, 32)
	_, err := rand.Read(msgHash)
	require.NoError(t, err)

	for i := 0; i < threshold+1; i++ {
		params := tss.NewParameters(tss.S256(), signCtx, signSubset[i], threshold+1, threshold)
		if i == 0 {
			params.SetBroker(tamper)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		// Find the full-committee index of signSubset[i] in the keygen
		// committee so we use the correct *Key for that party.
		sIdx := -1
		for n, p := range pIDs {
			if p.KeyInt().Cmp(signSubset[i].KeyInt()) == 0 {
				sIdx = n
				break
			}
		}
		require.GreaterOrEqual(t, sIdx, 0)
		sp, err := NewSigning(context.Background(), params, keys[sIdx], msgHash, signSubset, nil)
		require.NoError(t, err)
		signings[i] = sp
	}

	// At least one non-equivocating party must surface a tss.Error
	// with the equivocator in Culprits().
	tamperPID := signSubset[0]
	sawAttribution := false
	deadline := time.After(2 * time.Minute)
	for i := 0; i < threshold+1; i++ {
		if i == 0 {
			continue
		}
		select {
		case <-signings[i].Done:
			t.Logf("party %d unexpectedly produced a signature", i)
		case e := <-signings[i].Err:
			require.Error(t, e)
			tssErr, ok := e.(*tss.Error)
			if !ok {
				continue
			}
			for _, c := range tssErr.Culprits() {
				if c.KeyInt().Cmp(tamperPID.KeyInt()) == 0 {
					sawAttribution = true
				}
			}
			t.Logf("party %d errored: %v", i, e)
		case <-deadline:
			t.Fatalf("party %d did not finish within deadline", i)
		}
	}
	require.True(t, sawAttribution,
		"echo phase must attribute K_i equivocation to the equivocating party (party 0)")
}

// TestPresignEquivocationCaughtByEcho parallels the signing test for
// the presigning path.
func TestPresignEquivocationCaughtByEcho(t *testing.T) {
	const partyCount, threshold = 4, 2 // 3 signers, so echo phase can triangulate
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)

	signSubset := pIDs[:threshold+1]
	hub := newTestHub(threshold + 1)
	signCtx := tss.NewPeerContext(signSubset)

	parties := make([]*PresignParty, threshold+1)
	tamperP := &kEquivocatingBroker{hubBroker: hub.brokers[0], msgType: presignTypeR1}
	for i := 0; i < threshold+1; i++ {
		params := tss.NewParameters(tss.S256(), signCtx, signSubset[i], threshold+1, threshold)
		if i == 0 {
			params.SetBroker(tamperP)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		sIdx := -1
		for n, p := range pIDs {
			if p.KeyInt().Cmp(signSubset[i].KeyInt()) == 0 {
				sIdx = n
				break
			}
		}
		require.GreaterOrEqual(t, sIdx, 0)
		pp, err := NewPresign(context.Background(), params, keys[sIdx], signSubset)
		require.NoError(t, err)
		parties[i] = pp
	}

	tamperPID := signSubset[0]
	sawAttribution := false
	deadline := time.After(2 * time.Minute)
	for i := 0; i < threshold+1; i++ {
		if i == 0 {
			continue
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
				}
			}
		case <-deadline:
			t.Fatalf("presign party %d did not finish", i)
		}
	}
	require.True(t, sawAttribution,
		"presign echo phase must attribute K_i equivocation to party 0")
}

// Ensure compile-time use of big.Int import.
var _ = big.NewInt
