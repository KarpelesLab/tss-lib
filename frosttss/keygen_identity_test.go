// Copyright © 2026 KarpelesLab.

package frosttss

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestKeygenRejectsIdentityCommitment verifies the audit fix HIGH-1: a
// malicious dealer that broadcasts phi_{j,0} = identity together with a
// valid Schnorr PoK of 0 must be rejected by every honest recipient, with
// the dealer's PartyID surfaced in Culprits().
//
// Without the fix the dealer's contribution to the joint secret is zero
// (it knows 0 trivially), biasing the joint key.
func TestKeygenRejectsIdentityCommitment(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)
	ec := edwards25519.Edwards()
	q := ec.Params().N

	// Honest parties 1 and 2 use NewKeygen.
	honest := make([]*Keygen, 2)
	for n, i := range []int{1, 2} {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		honest[n] = kg
	}

	// Party 0 manually crafts a malicious round-1 broadcast:
	//   phi_0 = (0, 1) — the Ed25519 identity.
	//   phi_1 = G       — base point (any valid non-identity for length).
	//   Schnorr PoK of 0 on phi_0: pick random r, α = r·G, T = r.
	//   Verification: T·G == α + c·O == r·G == α. ✓
	identityPoint, err := crypto.NewECPoint(ec, big.NewInt(0), big.NewInt(1))
	require.NoError(t, err)
	require.True(t, identityPoint.IsIdentity())

	basePoint, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	require.NoError(t, err)

	// Sample r ∈ [1, q) — the Schnorr commitment randomness.
	r := common.GetRandomPositiveInt(rand.Reader, q)
	alpha, err := basePoint.ScalarMult(r), error(nil)
	require.NoError(t, err)

	commit0 := frost.EncodeElement(identityPoint)
	commit1 := frost.EncodeElement(basePoint)

	sessionNonce := make([]byte, keygenSessionNonceLen)
	_, err = rand.Read(sessionNonce)
	require.NoError(t, err)

	maliciousMsg := &keygenRound1msg{
		PolyCommitments:    [][]byte{commit0, commit1},
		SessionNonce:       sessionNonce,
		SchnorrProofAlphaX: alpha.X().Bytes(),
		SchnorrProofAlphaY: alpha.Y().Bytes(),
		SchnorrProofT:      r.Bytes(),
	}
	wrapped := tss.JsonWrap("frost:ed25519:keygen:round1", maliciousMsg, pIDs[0], nil)
	require.NoError(t, hub.brokers[0].Receive(wrapped))

	// Each honest party should error out with party 0 as culprit.
	for n, i := range []int{1, 2} {
		select {
		case key := <-honest[n].Done:
			t.Fatalf("party %d unexpectedly produced a Key (master pub=%s)", i, key.GroupPublicKey.X())
		case e := <-honest[n].Err:
			require.Error(t, e)
			require.True(t,
				strings.Contains(e.Error(), "identity"),
				"party %d error should mention identity rejection: %v", i, e)
			tssErr, ok := e.(*tss.Error)
			require.True(t, ok, "party %d error must be *tss.Error to carry Culprits()", i)
			culprits := tssErr.Culprits()
			require.NotEmpty(t, culprits, "party %d Culprits() must include the dealer", i)
			require.Equal(t, pIDs[0].KeyInt().String(), culprits[0].KeyInt().String(),
				"party %d Culprits() must name party 0", i)
		case <-time.After(time.Minute):
			t.Fatalf("party %d did not error within timeout", i)
		}
	}
}

// TestKeygenRejectsNonCanonicalSchnorrT verifies the range-check on the
// Schnorr proof's response scalar T: encoding T+k·L is rejected even
// though it would mathematically satisfy the verification equation.
// This closes a wire-malleability footprint.
func TestKeygenRejectsNonCanonicalSchnorrT(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)
	ec := edwards25519.Edwards()
	q := ec.Params().N

	honest := make([]*Keygen, 2)
	for n, i := range []int{1, 2} {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		honest[n] = kg
	}

	// Build a normally-valid round-1 message but with T inflated by +L.
	// First produce a valid (vs, PoK) via the live API, then resign with
	// T_inflated = T + L.
	params0 := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[0], partyCount, threshold)
	params0.SetBroker(hub.brokers[0])
	tap := &roundOneTapBroker{
		hubBroker: hub.brokers[0],
		captured:  make(chan *keygenRound1msg, 1),
	}
	params0.SetBroker(tap)

	// Don't actually run NewKeygen — we need to build the malicious
	// message off-line. Instead, generate a fresh polynomial + PoK using
	// the same internal helpers, then mutate T.
	a_i_0 := common.GetRandomPositiveInt(rand.Reader, q)
	basePoint, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	require.NoError(t, err)
	phi0 := basePoint.ScalarMult(a_i_0)
	// Generate phi_1 = random nonzero coefficient * G.
	a_i_1 := common.GetRandomPositiveInt(rand.Reader, q)
	phi1 := basePoint.ScalarMult(a_i_1)

	sessionNonce := make([]byte, keygenSessionNonceLen)
	_, err = rand.Read(sessionNonce)
	require.NoError(t, err)

	// Construct a valid Schnorr PoK manually so we can mutate T.
	// α = r·G, c = H(session, phi0, G, α), T_honest = r + c·a_{i,0} mod q.
	// We'll build it via the existing helper, then inflate T.
	r := common.GetRandomPositiveInt(rand.Reader, q)
	alpha := basePoint.ScalarMult(r)
	// Mirror the schnorr_proof challenge construction: hashed session ||
	// phi0 || G || α. Use the package-private buildKeygenSession.
	session := buildKeygenSession(pIDs[0].KeyInt(), sessionNonce)
	c := common.RejectionSample(q, common.SHA512_256i_TAGGED(
		session, phi0.X(), phi0.Y(),
		basePoint.X(), basePoint.Y(),
		alpha.X(), alpha.Y(),
	))
	tHonest := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(c, a_i_0)), q)
	// Inflate T by adding L (curve order) — mathematically equivalent
	// scalar, non-canonical encoding.
	tInflated := new(big.Int).Add(tHonest, q)
	require.True(t, tInflated.Cmp(q) >= 0, "tInflated must be >= q to exercise the range check")

	mal := &keygenRound1msg{
		PolyCommitments:    [][]byte{frost.EncodeElement(phi0), frost.EncodeElement(phi1)},
		SessionNonce:       sessionNonce,
		SchnorrProofAlphaX: alpha.X().Bytes(),
		SchnorrProofAlphaY: alpha.Y().Bytes(),
		SchnorrProofT:      tInflated.Bytes(),
	}
	wrapped := tss.JsonWrap("frost:ed25519:keygen:round1", mal, pIDs[0], nil)
	require.NoError(t, hub.brokers[0].Receive(wrapped))

	// Either honest party should error out with the canonicalization
	// complaint and party 0 as culprit.
	for n, i := range []int{1, 2} {
		select {
		case <-honest[n].Done:
			t.Fatalf("party %d unexpectedly produced a Key", i)
		case e := <-honest[n].Err:
			require.Error(t, e)
			require.True(t,
				strings.Contains(e.Error(), "canonical") ||
					strings.Contains(e.Error(), ">= L"),
				"party %d error should mention canonicalization: %v", i, e)
			tssErr, ok := e.(*tss.Error)
			require.True(t, ok)
			require.Equal(t, pIDs[0].KeyInt().String(), tssErr.Culprits()[0].KeyInt().String())
		case <-time.After(time.Minute):
			t.Fatalf("party %d did not error within timeout", i)
		}
	}
}
