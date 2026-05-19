package dklstss

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// runDistributedKeygen drives a KeygenParty per party against a fresh
// hub broker; returns the per-party keys in the order pIDs are given.
func runDistributedKeygen(t *testing.T, pIDs tss.SortedPartyIDs, threshold int) []*Key {
	t.Helper()
	n := len(pIDs)
	hub := newTestHub(n)
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*KeygenParty, n)
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], n, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		parties[i] = kg
	}
	keys := make([]*Key, n)
	for i, p := range parties {
		select {
		case k := <-p.Done:
			keys[i] = k
		case err := <-p.Err:
			t.Fatalf("keygen party %d failed: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("keygen party %d timeout", i)
		}
	}
	return keys
}

// TestSigningPartyEndToEnd runs distributed keygen followed by a
// distributed signing with a T+1 subset; verifies the resulting
// signature.
func TestSigningPartyEndToEnd(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)

	// Sign with parties {0, 2}.
	subsetIdx := []int{0, 2}
	subset := tss.SortedPartyIDs{pIDs[subsetIdx[0]], pIDs[subsetIdx[1]]}

	hub := newTestHub(partyCount)
	parties := make([]*SigningParty, len(subset))
	msg := sha256.Sum256([]byte("party signing"))

	p2pCtx := tss.NewPeerContext(pIDs)
	for n, sIdx := range subsetIdx {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[sIdx], partyCount, threshold)
		// Each signer uses its own broker indexed by its full-committee position.
		params.SetBroker(hub.brokers[sIdx])
		sp, err := NewSigning(context.Background(), params, keys[sIdx], msg[:], subset, nil)
		require.NoError(t, err)
		parties[n] = sp
	}

	sigs := make([]*Signature, len(parties))
	for i, p := range parties {
		select {
		case s := <-p.Done:
			sigs[i] = s
		case err := <-p.Err:
			t.Fatalf("signing party %d failed: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("signing party %d timeout", i)
		}
	}

	// All signers produced the same signature.
	for i := 1; i < len(sigs); i++ {
		assert.Equal(t, sigs[0].R.String(), sigs[i].R.String(), "R mismatch between signers")
		assert.Equal(t, sigs[0].S.String(), sigs[i].S.String(), "S mismatch between signers")
	}

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sigs[0].R, sigs[0].S))
}

// TestSigningPartyWithHDTweak runs distributed signing with a non-nil
// HD tweak; the signature must verify under the derived child pubkey,
// not the parent.
func TestSigningPartyWithHDTweak(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)

	path := []uint32{44, 0, 0, 5}
	tweak, childPub, err := DeriveChild(keys[0], path)
	require.NoError(t, err)

	subsetIdx := []int{0, 1}
	subset := tss.SortedPartyIDs{pIDs[subsetIdx[0]], pIDs[subsetIdx[1]]}
	hub := newTestHub(partyCount)
	msg := sha256.Sum256([]byte("party HD signing"))

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*SigningParty, len(subset))
	for n, sIdx := range subsetIdx {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[sIdx], partyCount, threshold)
		params.SetBroker(hub.brokers[sIdx])
		sp, err := NewSigning(context.Background(), params, keys[sIdx], msg[:], subset, tweak)
		require.NoError(t, err)
		parties[n] = sp
	}

	var sig *Signature
	for i, p := range parties {
		select {
		case s := <-p.Done:
			if i == 0 {
				sig = s
			}
		case err := <-p.Err:
			t.Fatalf("signing party %d failed: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("signing party %d timeout", i)
		}
	}

	pub := &ecdsa.PublicKey{
		Curve: childPub.Curve(),
		X:     childPub.X(),
		Y:     childPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S), "HD-tweaked party signature must verify under child pubkey")

	parent := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.False(t, ecdsa.Verify(parent, msg[:], sig.R, sig.S), "signature must NOT verify under parent")
}

// TestSigningPartyRepeatedSignReusesOTSafely runs two distributed
// signings of the SAME message with the SAME subset against a single
// keygen. Each ΠMul invocation reuses the OT-extension state from
// keygen, which is the worst case for the OT-extension PRG: signSession
// alone would have produced identical sids across the two calls. With
// the per-call ssid mix that folds every K_i into the round-2 sid, the
// effective sid is freshly random per signing and both signatures
// verify under the same public key.
func TestSigningPartyRepeatedSignReusesOTSafely(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)

	subsetIdx := []int{0, 1}
	subset := tss.SortedPartyIDs{pIDs[subsetIdx[0]], pIDs[subsetIdx[1]]}
	msg := sha256.Sum256([]byte("same-message-twice"))
	p2pCtx := tss.NewPeerContext(pIDs)

	runOnce := func() *Signature {
		hub := newTestHub(partyCount)
		parties := make([]*SigningParty, len(subset))
		for n, sIdx := range subsetIdx {
			params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[sIdx], partyCount, threshold)
			params.SetBroker(hub.brokers[sIdx])
			sp, err := NewSigning(context.Background(), params, keys[sIdx], msg[:], subset, nil)
			require.NoError(t, err)
			parties[n] = sp
		}
		var got *Signature
		for i, p := range parties {
			select {
			case s := <-p.Done:
				if i == 0 {
					got = s
				}
			case err := <-p.Err:
				t.Fatalf("signing party %d failed: %v", i, err)
			case <-time.After(5 * time.Minute):
				t.Fatalf("signing party %d timeout", i)
			}
		}
		return got
	}

	sig1 := runOnce()
	sig2 := runOnce()

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig1.R, sig1.S), "first signature must verify")
	assert.True(t, ecdsa.Verify(pub, msg[:], sig2.R, sig2.S), "second signature must verify")
	// The two runs use independent nonces; R values should differ.
	assert.NotEqual(t, sig1.R.String(), sig2.R.String(), "R should be freshly random per signing")
}
