package dklstss

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// runDistributedPresign drives a PresignParty per signer against a
// fresh hub broker; returns the per-party PresignOutputs in the order
// of signerIdx.
func runDistributedPresign(t *testing.T, keys []*Key, pIDs tss.SortedPartyIDs, signerIdx []int) []*PresignOutput {
	t.Helper()
	subset := make(tss.SortedPartyIDs, len(signerIdx))
	for i, idx := range signerIdx {
		subset[i] = pIDs[idx]
	}

	n := len(pIDs)
	hub := newTestHub(n)
	p2pCtx := tss.NewPeerContext(pIDs)

	parties := make([]*PresignParty, len(signerIdx))
	for i, sIdx := range signerIdx {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[sIdx], n, keys[0].T)
		params.SetBroker(hub.brokers[sIdx])
		pp, err := NewPresign(context.Background(), params, keys[sIdx], subset)
		require.NoError(t, err)
		parties[i] = pp
	}

	outs := make([]*PresignOutput, len(signerIdx))
	for i, p := range parties {
		select {
		case out := <-p.Done:
			outs[i] = out
		case err := <-p.Err:
			t.Fatalf("presign party %d failed: %v", i, err)
		case <-time.After(60 * time.Second):
			t.Fatalf("presign party %d timeout", i)
		}
	}
	return outs
}

// TestPresignPartyEndToEnd runs distributed presign and verifies that
// the per-party PresignOutputs are internally consistent.
func TestPresignPartyEndToEnd(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)

	signerIdx := []int{0, 2}
	outs := runDistributedPresign(t, keys, pIDs, signerIdx)
	require.Len(t, outs, len(signerIdx))

	// All parties should agree on R, r, and Pub.
	for i := 1; i < len(outs); i++ {
		assert.Truef(t, outs[0].R.Equals(outs[i].R), "R differs at signer %d", i)
		assert.Equalf(t, outs[0].r.String(), outs[i].r.String(), "r differs at signer %d", i)
		assert.Truef(t, outs[0].Pub.Equals(outs[i].Pub), "Pub differs at signer %d", i)
	}

	// Combine per-party shares to reconstruct φ and verify k·ρ
	// consistency via the public-key check: φ = k · ρ, so
	// (Σ kRhoShare) · G should equal ... well, we don't have ρ to
	// check directly. Instead, fall back to a sign step:
	//
	//   ŝ = Σ (ρ_i · H(m) + r · σ_i)
	//   s = ŝ · φ⁻¹
	//
	// then verify the ECDSA signature.
	q := tss.S256().Params().N
	msg := sha256.Sum256([]byte("presign-party end-to-end"))
	hashI := new(big.Int).SetBytes(msg[:])
	hashI.Mod(hashI, q)

	phi := new(big.Int)
	shat := new(big.Int)
	for _, out := range outs {
		p := out.parties[0]
		phi.Add(phi, p.kRhoShare)
		phi.Mod(phi, q)

		t1 := new(big.Int).Mul(p.rho, hashI)
		t1.Mod(t1, q)
		t2 := new(big.Int).Mul(outs[0].r, p.sigma)
		t2.Mod(t2, q)
		s_i := new(big.Int).Add(t1, t2)
		s_i.Mod(s_i, q)
		shat.Add(shat, s_i)
		shat.Mod(shat, q)
	}
	phiInv := common.ModInt(q).ModInverse(phi)
	require.NotNil(t, phiInv)
	s := new(big.Int).Mul(shat, phiInv)
	s.Mod(s, q)
	halfQ := new(big.Int).Rsh(q, 1)
	if s.Cmp(halfQ) > 0 {
		s.Sub(q, s)
	}

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], outs[0].r, s),
		"presigned parts compose to a valid ECDSA signature")
}

// TestPresignPartyRepeatedReusesOTSafely runs two distributed presigns
// against the same key + same signer subset. presignSession is fully
// determined by (pub, subset) so without the round-2 K_i mix the two
// calls would produce identical ΠMul sids and reuse the long-term OT
// extension state with matching (seed, sid) — exactly the precondition
// that pre-fix leaked the choice-bit XOR via the wire `u` rows. The
// mix folds every signer's K_i into the round-2 ssid, making the
// effective sid freshly random per call; both presigns must complete
// and produce distinct R values.
func TestPresignPartyRepeatedReusesOTSafely(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)
	signerIdx := []int{0, 2}

	out1 := runDistributedPresign(t, keys, pIDs, signerIdx)
	out2 := runDistributedPresign(t, keys, pIDs, signerIdx)
	require.Len(t, out1, len(signerIdx))
	require.Len(t, out2, len(signerIdx))

	// Each signer's locally-held R must agree within one call but
	// differ between calls — fresh nonces per presign.
	for i := 1; i < len(out1); i++ {
		assert.Truef(t, out1[0].R.Equals(out1[i].R), "first-run R differs at signer %d", i)
		assert.Truef(t, out2[0].R.Equals(out2[i].R), "second-run R differs at signer %d", i)
	}
	assert.Falsef(t, out1[0].R.Equals(out2[0].R),
		"two presigns should produce distinct group nonce R (fresh k_i per call)")
}
