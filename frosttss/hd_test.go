// Copyright © 2026 KarpelesLab.

package frosttss

import (
	"bytes"
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestDeriveChainCodeDeterministic asserts that DeriveChainCode is a
// pure function of GroupPublicKey: the same pub yields the same 32-byte
// chain code, and different pubs yield different chain codes.
func TestDeriveChainCodeDeterministic(t *testing.T) {
	ec := edwards25519.Edwards()
	a := crypto.CTScalarBaseMultEd25519(ec, big.NewInt(7))
	b := crypto.CTScalarBaseMultEd25519(ec, big.NewInt(11))

	ccA1 := DeriveChainCode(a)
	ccA2 := DeriveChainCode(a)
	ccB := DeriveChainCode(b)

	require.Len(t, ccA1, 32, "chain code must be 32 bytes")
	require.Equal(t, ccA1, ccA2, "DeriveChainCode must be deterministic for the same pub")
	require.NotEqual(t, ccA1, ccB, "different pubs must yield different chain codes")
	require.Nil(t, DeriveChainCode(nil), "nil pub returns nil")
}

// TestDeriveChildPathSemantics asserts that:
//   - An empty path is a no-op (tweak=0, childPub=parent, chainCode=parent CC).
//   - Walking the same path twice yields the same (tweak, childPub, chainCode).
//   - Different paths yield different childPubs.
//   - Hardened indices (≥ 2^31) are rejected.
//   - childPub = parent_pub + tweak·G holds.
func TestDeriveChildPathSemantics(t *testing.T) {
	ec := edwards25519.Edwards()
	parentScalar := big.NewInt(0x123456789ABCDEF)
	parentPub := crypto.CTScalarBaseMultEd25519(ec, parentScalar)
	key := &Key{
		Xi:             parentScalar,
		ShareID:        big.NewInt(1),
		Ks:             []*big.Int{big.NewInt(1)},
		BigXj:          []*crypto.ECPoint{parentPub},
		GroupPublicKey: parentPub,
		ChainCode:      DeriveChainCode(parentPub),
	}

	// Empty path: tweak=0, childPub=parent.
	tweak, childPub, childCC, err := key.DeriveChild(nil)
	require.NoError(t, err)
	require.Equal(t, 0, tweak.Sign(), "empty path must yield tweak=0")
	require.True(t, childPub.Equals(parentPub), "empty path must yield parent pub")
	require.Equal(t, key.ChainCode, childCC, "empty path must yield parent chain code")

	// Determinism.
	tweak1, child1, cc1, err := key.DeriveChild([]uint32{0, 1, 7})
	require.NoError(t, err)
	tweak2, child2, cc2, err := key.DeriveChild([]uint32{0, 1, 7})
	require.NoError(t, err)
	require.Equal(t, tweak1.String(), tweak2.String(), "derivation must be deterministic")
	require.True(t, child1.Equals(child2))
	require.Equal(t, cc1, cc2)

	// Different paths -> different children.
	_, child3, _, err := key.DeriveChild([]uint32{0, 1, 8})
	require.NoError(t, err)
	require.False(t, child1.Equals(child3), "different paths must yield different children")

	// childPub = parentPub + tweak · G.
	deltaG := crypto.CTScalarBaseMultEd25519(ec, tweak1)
	expected, err := parentPub.Add(deltaG)
	require.NoError(t, err)
	require.True(t, child1.Equals(expected), "childPub = parentPub + tweak·G must hold")

	// Hardened rejection.
	_, _, _, err = key.DeriveChild([]uint32{HardenedKeyStart})
	require.ErrorIs(t, err, ErrHardenedNotSupported)
	_, _, _, err = key.DeriveChild([]uint32{0, HardenedKeyStart + 5, 1})
	require.ErrorIs(t, err, ErrHardenedNotSupported)
}

// TestKeyValidateBasicAcceptsNilChainCode verifies the backward-compat
// guarantee: legacy Version-1 Keys (with no ChainCode) still pass
// ValidateBasic.
func TestKeyValidateBasicAcceptsNilChainCode(t *testing.T) {
	ec := edwards25519.Edwards()
	xi := big.NewInt(987654321)
	pub := crypto.CTScalarBaseMultEd25519(ec, xi)
	id := big.NewInt(1)
	k := &Key{
		Xi:             xi,
		ShareID:        id,
		Ks:             []*big.Int{id},
		BigXj:          []*crypto.ECPoint{pub},
		GroupPublicKey: pub,
		// ChainCode intentionally nil.
	}
	require.NoError(t, k.ValidateBasic(), "Key without ChainCode must still validate (backward compat)")

	// Setting an invalid-length ChainCode must error.
	k.ChainCode = []byte{0x01, 0x02, 0x03}
	require.Error(t, k.ValidateBasic(), "ChainCode of wrong length must fail validation")

	// Canonical 32-byte chain code must validate.
	k.ChainCode = DeriveChainCode(pub)
	require.NoError(t, k.ValidateBasic())
}

// TestAttachChainCodeIdempotent confirms a legacy Key can be upgraded
// and that re-attaching produces the same value.
func TestAttachChainCodeIdempotent(t *testing.T) {
	ec := edwards25519.Edwards()
	xi := big.NewInt(42)
	pub := crypto.CTScalarBaseMultEd25519(ec, xi)
	id := big.NewInt(1)
	k := &Key{
		Xi:             xi,
		ShareID:        id,
		Ks:             []*big.Int{id},
		BigXj:          []*crypto.ECPoint{pub},
		GroupPublicKey: pub,
	}
	require.Nil(t, k.ChainCode)
	require.NoError(t, k.AttachChainCode())
	cc1 := append([]byte(nil), k.ChainCode...)
	require.Len(t, cc1, 32)

	require.NoError(t, k.AttachChainCode())
	require.Equal(t, cc1, k.ChainCode, "AttachChainCode must be idempotent")
}

// TestKeygenPopulatesChainCode validates that NewKeygen output now
// carries ChainCode = DeriveChainCode(GroupPublicKey), and that every
// party agrees on its value.
func TestKeygenPopulatesChainCode(t *testing.T) {
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
			t.Fatalf("keygen %d: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("keygen %d timed out", i)
		}
	}

	want := DeriveChainCode(keys[0].GroupPublicKey)
	require.Len(t, want, 32)
	for i, k := range keys {
		require.Equal(t, want, k.ChainCode, "party %d ChainCode disagrees with party 0", i)
	}
}

// TestDerivedSignVerifies is the end-to-end test: 5-party keygen at
// threshold 2, derive a non-trivial path, sign with the t+1 committee,
// verify the resulting signature under the DERIVED public key using a
// standard Ed25519 verifier. If tweak absorption is wrong, this fails.
func TestDerivedSignVerifies(t *testing.T) {
	const (
		partyCount = 5
		threshold  = 2 // t+1 = 3 signers
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
			t.Fatalf("keygen %d: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("keygen %d timed out", i)
		}
	}

	path := []uint32{44, 60, 0, 0, 7}
	// Every party derives independently from the same public Key data.
	tweak, childPub, _, err := keys[0].DeriveChild(path)
	require.NoError(t, err)
	require.NotNil(t, childPub)

	// Cross-check every other party derives the same childPub & tweak.
	for i := 1; i < partyCount; i++ {
		tweakI, childPubI, _, err := keys[i].DeriveChild(path)
		require.NoError(t, err)
		require.Equal(t, tweak.String(), tweakI.String(),
			"party %d derived a different tweak from the same path", i)
		require.True(t, childPub.Equals(childPubI),
			"party %d derived a different childPub from the same path", i)
	}

	// Pick a signing subset: parties {0, 2, 4} (non-contiguous to exercise
	// SubsetForParties together with tweak absorption). The subset's
	// PartyIDs must be re-numbered with indices 0..len(subset)-1 — the
	// hubBroker routes by msg.To.Index, and the original pIDs[2], pIDs[4]
	// carry indices 2 and 4 which would route to non-existent brokers.
	selected := []int{0, 2, 4}
	var unsorted tss.UnSortedPartyIDs
	for _, k := range selected {
		orig := pIDs[k]
		unsorted = append(unsorted, tss.NewPartyID(orig.Id, orig.Moniker, orig.KeyInt()))
	}
	subset := tss.SortPartyIDs(unsorted)

	signingHub := newTestHub(len(subset))
	subsetCtx := tss.NewPeerContext(subset)

	msg := []byte("frost-ed25519 HD derive-and-sign roundtrip")

	signings := make([]*Signing, len(subset))
	for n, pid := range subset {
		params := tss.NewParameters(tss.Edwards(), subsetCtx, pid, len(subset), threshold)
		params.SetBroker(signingHub.brokers[n])

		// Look up the keygen index for this PartyID by key bytes.
		var keyIdx int
		for j, p := range pIDs {
			if bytes.Equal(p.Key, pid.Key) {
				keyIdx = j
				break
			}
		}
		sg, err := keys[keyIdx].NewSigningWithTweak(context.Background(), msg, params, tweak)
		require.NoError(t, err)
		signings[n] = sg
	}

	sigs := make([]*SignatureData, len(subset))
	for n := range signings {
		select {
		case sig := <-signings[n].Done:
			sigs[n] = sig
		case err := <-signings[n].Err:
			t.Fatalf("signer %d: %v", n, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("signer %d timed out", n)
		}
	}

	// All parties produced the same signature.
	for n := 1; n < len(subset); n++ {
		assert.Equal(t, sigs[0].Signature, sigs[n].Signature, "signer %d signature mismatch", n)
	}
	require.Len(t, sigs[0].Signature, 64)

	// CRITICAL: verifies under the DERIVED public key (childPub), not
	// the parent. If tweak absorption is wrong (e.g., absorbed by the
	// wrong signer, or challenge computed under parentPub) this fails.
	pkChild := &edwards25519.PublicKey{
		Curve: tss.Edwards(),
		X:     childPub.X(),
		Y:     childPub.Y(),
	}
	parsed, err := edwards25519.ParseSignature(sigs[0].Signature)
	require.NoError(t, err)
	require.True(t, edwards25519.VerifyRS(pkChild, msg, parsed.R, parsed.S),
		"HD signature must verify under derived child pubkey")

	// AND it must NOT verify under the parent pubkey (sanity check —
	// the tweak should actually matter).
	pkParent := &edwards25519.PublicKey{
		Curve: tss.Edwards(),
		X:     keys[0].GroupPublicKey.X(),
		Y:     keys[0].GroupPublicKey.Y(),
	}
	require.False(t, edwards25519.VerifyRS(pkParent, msg, parsed.R, parsed.S),
		"HD signature must NOT verify under parent pubkey (would mean tweak was a no-op)")
}

// TestSignWithTweakNilEquivalentToNewSigning verifies that
// NewSigningWithTweak(nil) is observationally equivalent to NewSigning
// — both produce a signature verifiable under the parent group public
// key. This is the API-compatibility guarantee.
func TestSignWithTweakNilEquivalentToNewSigning(t *testing.T) {
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
			t.Fatalf("keygen %d: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("keygen %d timed out", i)
		}
	}

	msg := []byte("tweak nil should equal no-tweak")
	signHub := newTestHub(partyCount)
	signings := make([]*Signing, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(signHub.brokers[i])
		// Explicitly nil tweak via the new entry point.
		sg, err := keys[i].NewSigningWithTweak(context.Background(), msg, params, nil)
		require.NoError(t, err)
		signings[i] = sg
	}
	for i := 0; i < partyCount; i++ {
		select {
		case sig := <-signings[i].Done:
			pkParent := &edwards25519.PublicKey{
				Curve: tss.Edwards(),
				X:     keys[0].GroupPublicKey.X(),
				Y:     keys[0].GroupPublicKey.Y(),
			}
			parsed, err := edwards25519.ParseSignature(sig.Signature)
			require.NoError(t, err)
			require.True(t, edwards25519.VerifyRS(pkParent, msg, parsed.R, parsed.S),
				"NewSigningWithTweak(nil) signature must verify under parent pubkey")
		case err := <-signings[i].Err:
			t.Fatalf("signer %d: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("signer %d timed out", i)
		}
	}
}

// TestImportKeyPopulatesChainCode confirms ImportKey now sets ChainCode
// so an imported key is immediately usable for HD derivation.
func TestImportKeyPopulatesChainCode(t *testing.T) {
	ec := edwards25519.Edwards()
	priv := big.NewInt(1)
	priv.Lsh(priv, 200) // a non-trivial scalar
	priv.Mod(priv, ec.Params().N)
	pid := tss.NewPartyID("importer", "importer", big.NewInt(99))

	k, err := ImportKey(priv, pid)
	require.NoError(t, err)
	require.Len(t, k.ChainCode, 32)
	require.Equal(t, DeriveChainCode(k.GroupPublicKey), k.ChainCode)

	// Confirm it can drive DeriveChild without AttachChainCode.
	tweak, childPub, _, err := k.DeriveChild([]uint32{0})
	require.NoError(t, err)
	require.NotNil(t, childPub)
	require.NotEqual(t, 0, tweak.Sign())
}

// TestDeriveAndSign is a sanity check that the convenience helper
// produces a verifiable signature against the returned childPub.
func TestDeriveAndSign(t *testing.T) {
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
			t.Fatalf("keygen %d: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("keygen %d timed out", i)
		}
	}

	path := []uint32{1, 2, 3}
	msg := []byte("DeriveAndSign convenience")
	signHub := newTestHub(partyCount)
	signings := make([]*Signing, partyCount)
	var sharedChildPub *crypto.ECPoint
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(signHub.brokers[i])
		sg, childPub, err := keys[i].DeriveAndSign(context.Background(), path, msg, params)
		require.NoError(t, err)
		signings[i] = sg
		if sharedChildPub == nil {
			sharedChildPub = childPub
		} else {
			require.True(t, sharedChildPub.Equals(childPub),
				"party %d derived a different childPub", i)
		}
	}
	for i := 0; i < partyCount; i++ {
		select {
		case sig := <-signings[i].Done:
			pkChild := &edwards25519.PublicKey{
				Curve: tss.Edwards(),
				X:     sharedChildPub.X(),
				Y:     sharedChildPub.Y(),
			}
			parsed, err := edwards25519.ParseSignature(sig.Signature)
			require.NoError(t, err)
			require.True(t, edwards25519.VerifyRS(pkChild, msg, parsed.R, parsed.S),
				"party %d DeriveAndSign signature failed verification under child pub", i)
		case err := <-signings[i].Err:
			t.Fatalf("party %d signing error: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("party %d signing timeout", i)
		}
	}
}

// TestDeriveChildMissingChainCode confirms a legacy Key (no ChainCode)
// errors clearly out of DeriveChild rather than crashing.
func TestDeriveChildMissingChainCode(t *testing.T) {
	ec := edwards25519.Edwards()
	xi := big.NewInt(7)
	pub := crypto.CTScalarBaseMultEd25519(ec, xi)
	id := big.NewInt(1)
	k := &Key{
		Xi:             xi,
		ShareID:        id,
		Ks:             []*big.Int{id},
		BigXj:          []*crypto.ECPoint{pub},
		GroupPublicKey: pub,
	}
	_, _, _, err := k.DeriveChild([]uint32{0})
	require.Error(t, err)
}

// silence the unused-import warning if frost is referenced only above.
var _ = frost.EdwardsCurve
