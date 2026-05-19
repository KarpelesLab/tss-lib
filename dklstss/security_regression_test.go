package dklstss

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestMakeSidNoTruncationAcross256Boundary verifies the audit fix that
// replaced makeSid's `byte(alice), byte(bob)` (truncating indexes to one
// byte) with a 4-byte big-endian encoding. With the v1 encoding the
// pair (0, 1) and the pair (256, 257) would produce identical sids; the
// new encoding must keep them distinct.
//
// Collisions in this sid would cause the OT-extension layer to derive
// identical per-call PRG outputs for unrelated party pairs in
// committees with 256+ members, which combined with seed reuse would
// reintroduce the choice-bit XOR leak that the prg.go fix closes.
func TestMakeSidNoTruncationAcross256Boundary(t *testing.T) {
	ssid := []byte("ssid")
	kind := "test"
	sid01 := makeSid(ssid, kind, 0, 1)
	sid256_257 := makeSid(ssid, kind, 256, 257)
	require.False(t, bytes.Equal(sid01, sid256_257),
		"makeSid(0,1) must not equal makeSid(256,257) — pre-fix the byte() truncation made them identical")

	// Also check a less obvious case: pairs whose low bytes match.
	sid42_43 := makeSid(ssid, kind, 42, 43)
	sid298_299 := makeSid(ssid, kind, 42+256, 43+256)
	require.False(t, bytes.Equal(sid42_43, sid298_299),
		"makeSid pairs differing only in the high byte must be distinct")

	// Sanity: same inputs are deterministic.
	sid01b := makeSid(ssid, kind, 0, 1)
	assert.Equal(t, sid01, sid01b, "makeSid must be deterministic on the same inputs")
}

// TestSyncSignRepeatedReusesOTSafely is the synchronous-Sign analogue of
// TestSigningPartyRepeatedSignReusesOTSafely. Each Sign() call samples
// its own ssidNonce, so even before the audit the SIDs were already
// nonced — but the OT-extension state is reused across calls, so this
// test exercises the prgExpand sid-binding fix from crypto/ot/otext.
// Without that fix the receiver's u rows on the wire would leak
// bitsLE(k_i⁽¹⁾) ⊕ bitsLE(k_i⁽²⁾) to the partner, and key extraction
// would follow with enough signings.
func TestSyncSignRepeatedReusesOTSafely(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	msg := sha256.Sum256([]byte("sync-repeated"))

	sig1, err := Sign(keys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	sig2, err := Sign(keys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig1.R, sig1.S), "first sync sign must verify")
	assert.True(t, ecdsa.Verify(pub, msg[:], sig2.R, sig2.S), "second sync sign must verify")
	assert.NotEqual(t, sig1.R.String(), sig2.R.String(),
		"two ECDSA signatures of the same hash should have different R (fresh nonces)")
}

// TestReshareRejectsZeroScaledShare exercises the post-audit error path
// in resharing.go where `λ_i · x_i mod q == 0`. Natural probability is
// ~ 2⁻²⁵⁶ so we manufacture the precondition by zeroing one
// participant's Xi (BigXj is left as-is — Reshare doesn't recompute or
// cross-check it before the scaled-share calculation, so the test
// reaches the intended branch). The pre-audit code silently substituted
// scaled = 1 and let the protocol continue, eventually hitting a
// confusing pubkey-mismatch error downstream; the new code returns a
// clear "λ·x_i ≡ 0" error before any VSS material is generated.
func TestReshareRejectsZeroScaledShare(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)

	// Surgically zero out the FIRST participant's share. We don't
	// touch BigXj — Reshare uses Xi directly to form the scaled share
	// and the bug's branch fires before any BigXj-derived check runs.
	keys[0].Xi = new(big.Int)

	newIDs := genPartyIDs(2)
	_, err = Reshare(keys, []int{0, 1}, newIDs, 1, rand.Reader)
	require.Error(t, err, "Reshare with Xi=0 must error rather than silently substituting")
	assert.Contains(t, err.Error(), "λ·x_i ≡ 0",
		"error must clearly identify the corrupted share rather than a misleading downstream pubkey mismatch")
}

// TestValidateBasicRejectsXiBigXjMismatch covers the M-3 audit fix:
// ValidateBasic now rejects a Key whose Xi · G doesn't equal
// BigXj[Idx]. The pre-fix loader accepted such mismatches (the algebra
// check was missing), and downstream signing produced a non-verifying
// signature with no surface clue that the share was tampered.
func TestValidateBasicRejectsXiBigXjMismatch(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	require.NoError(t, keys[0].ValidateBasic())

	// Flip Xi without updating BigXj[Idx] — the algebraic binding
	// breaks and ValidateBasic must catch it.
	bad := *keys[0]
	bad.Xi = new(big.Int).Add(keys[0].Xi, big.NewInt(1))
	bad.Xi.Mod(bad.Xi, tss.S256().Params().N)
	err = bad.ValidateBasic()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "share / public-commitment binding")
}

// TestLoadRejectsXiBigXjMismatch covers the M-3 audit fix at the
// serialization boundary: a tampered keyfile whose Xi has been bumped
// without re-running keygen must be rejected at Load.
func TestLoadRejectsXiBigXjMismatch(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, keys[0].Save(&buf))

	// Tamper with the on-disk xi value. The Xi field is a *big.Int
	// serialized as a raw JSON number (no quotes).
	original := keys[0].Xi.String()
	tampered := new(big.Int).Add(keys[0].Xi, big.NewInt(1))
	tampered.Mod(tampered, tss.S256().Params().N)
	rewritten := bytes.Replace(buf.Bytes(),
		[]byte("\"xi\":"+original),
		[]byte("\"xi\":"+tampered.String()),
		1)
	require.False(t, bytes.Equal(buf.Bytes(), rewritten), "xi rewrite must have changed the bytes")

	_, err = Load(bytes.NewReader(rewritten))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "share / public-commitment binding")
}

// TestNewResharingRequiresOldECDSAPub covers the C-1 audit fix:
// NewResharing must refuse to start without a valid oldECDSAPub. The
// previous API took only oldKey, leaving NEW-only parties with no local
// way to bind the resharing to a specific public key and letting a
// single malicious OLD participant rotate the joint key silently.
func TestNewResharingRequiresOldECDSAPub(t *testing.T) {
	oldKeys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	newPIDs := genPartyIDsOffset(2, 9000)
	combined := append(tss.UnSortedPartyIDs(nil), oldKeys[0].PartyIDs...)
	combined = append(combined, newPIDs...)
	combinedSorted := tss.SortPartyIDs(combined)
	combinedCtx := tss.NewPeerContext(combinedSorted)

	params := tss.NewParameters(tss.S256(), combinedCtx, oldKeys[0].PartyIDs[0], len(combinedSorted), 1)
	params.SetBroker(tss.NewTestBroker())

	_, err = NewResharing(context.Background(), params, nil, oldKeys[0], oldKeys[0].PartyIDs, newPIDs, 1)
	require.Error(t, err, "nil oldECDSAPub must be rejected")
	assert.Contains(t, err.Error(), "oldECDSAPub")
}

// TestNewResharingRejectsMismatchedOldECDSAPub covers the C-1 audit fix
// from the OLD-side: an OLD participant whose oldKey.ECDSAPub disagrees
// with the advertised oldECDSAPub must refuse to start. Otherwise a
// caller could trick an OLD party into participating in a resharing
// bound to a different key than the one they actually hold.
func TestNewResharingRejectsMismatchedOldECDSAPub(t *testing.T) {
	keysA, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	keysB, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)
	require.False(t, keysA[0].ECDSAPub.Equals(keysB[0].ECDSAPub))

	newPIDs := genPartyIDsOffset(2, 9100)
	combined := append(tss.UnSortedPartyIDs(nil), keysA[0].PartyIDs...)
	combined = append(combined, newPIDs...)
	combinedSorted := tss.SortPartyIDs(combined)
	combinedCtx := tss.NewPeerContext(combinedSorted)

	params := tss.NewParameters(tss.S256(), combinedCtx, keysA[0].PartyIDs[0], len(combinedSorted), 1)
	params.SetBroker(tss.NewTestBroker())

	_, err = NewResharing(context.Background(), params, keysB[0].ECDSAPub, keysA[0], keysA[0].PartyIDs, newPIDs, 1)
	require.Error(t, err, "mismatched oldECDSAPub vs oldKey.ECDSAPub must be rejected")
	assert.Contains(t, err.Error(), "does not match")
}

// TestResharingPartyDetectsMalformedOldContribution covers the C-1
// audit fix end-to-end: when an OLD participant ships VSS shares whose
// constant term doesn't sum to the advertised oldECDSAPub, the NEW
// committee must abort rather than silently accept a rotated key.
//
// The attack model: tamper one OLD party's Xi between keygen and
// resharing. The party will scale a wrong secret, so Σ V_old_i[0]
// reconstructs to (oldPub + (Δλ_M · Δ) · G), which differs from the
// advertised oldECDSAPub. finalize must catch this.
func TestResharingPartyDetectsMalformedOldContribution(t *testing.T) {
	const oldN, oldT = 2, 1
	oldPIDs := tss.GenerateTestPartyIDs(oldN)
	oldKeys := runDistributedKeygen(t, oldPIDs, oldT)
	oldPub := oldKeys[0].ECDSAPub

	// Tamper party 0's Xi so its scaled share contributes a different
	// constant term to the new committee. We also adjust BigXj[Idx] to
	// match (so ValidateBasic still passes on the tampered Key — M-3's
	// cross-check catches a NAIVE tamper at constructor time; the C-1
	// finalize check is what catches this CONSISTENT tamper at the
	// protocol level). The pre-fix code would build a new Key under
	// the rotated pub silently; the post-fix code must abort.
	q := tss.S256().Params().N
	tampered := *oldKeys[0]
	tampered.Xi = new(big.Int).Add(oldKeys[0].Xi, big.NewInt(1))
	tampered.Xi.Mod(tampered.Xi, q)
	tampered.BigXj = append([]*crypto.ECPoint(nil), oldKeys[0].BigXj...)
	tampered.BigXj[tampered.Idx] = crypto.ScalarBaseMult(tss.S256(), tampered.Xi)
	require.NoError(t, tampered.ValidateBasic(), "tampered key should still pass ValidateBasic (Xi and BigXj[Idx] both flipped)")
	oldKeys[0] = &tampered

	newPIDs := genPartyIDsOffset(2, 9200)
	const newT = 1
	combined := append(tss.UnSortedPartyIDs(nil), oldPIDs...)
	combined = append(combined, newPIDs...)
	combinedSorted := tss.SortPartyIDs(combined)
	combinedCtx := tss.NewPeerContext(combinedSorted)
	oldSubset := tss.SortedPartyIDs{oldPIDs[0], oldPIDs[1]}

	hub := newTestHub(len(combinedSorted))
	pidIdx := map[string]int{}
	for i, p := range combinedSorted {
		pidIdx[p.KeyInt().String()] = i
	}

	for _, p := range oldSubset {
		oldIdx := -1
		for i, q := range oldPIDs {
			if q.KeyInt().Cmp(p.KeyInt()) == 0 {
				oldIdx = i
				break
			}
		}
		params := tss.NewParameters(tss.S256(), combinedCtx, p, len(combinedSorted), oldT)
		params.SetBroker(hub.brokers[pidIdx[p.KeyInt().String()]])
		_, err := NewResharing(context.Background(), params, oldPub, oldKeys[oldIdx], oldSubset, newPIDs, newT)
		require.NoError(t, err)
	}

	// Spawn NEW parties; at least one of them must surface the
	// inconsistency on its Err channel.
	var newParties []*ResharingParty
	for _, p := range newPIDs {
		params := tss.NewParameters(tss.S256(), combinedCtx, p, len(combinedSorted), newT)
		params.SetBroker(hub.brokers[pidIdx[p.KeyInt().String()]])
		rp, err := NewResharing(context.Background(), params, oldPub, nil, oldSubset, newPIDs, newT)
		require.NoError(t, err)
		newParties = append(newParties, rp)
	}

	sawAbort := false
	for i, rp := range newParties {
		select {
		case k := <-rp.Done:
			t.Fatalf("party %d completed with key %v despite tampered OLD contribution", i, k)
		case err := <-rp.Err:
			require.Error(t, err)
			if assert.Contains(t, err.Error(), "reconstructed public key") {
				sawAbort = true
			}
		case <-time.After(5 * time.Minute):
			t.Fatalf("party %d neither completed nor aborted", i)
		}
	}
	require.True(t, sawAbort, "at least one new party must abort with the pubkey-mismatch error")
}

// equivocatingBroker wraps the standard test hubBroker so a specified
// sender can ship different bytes to different recipients under a
// single To==nil broadcast — i.e., the application-level equivocation
// scenario that the echo-broadcast defense is designed to catch.
//
// When perRecipientOverride[msgType][recipientIdx] is set and the
// wrapped party emits a To==nil message of that type, the broker
// replaces msg.Data with the override before forwarding to that
// recipient. Other (msgType, recipient) combinations and other senders
// route normally.
type equivocatingBroker struct {
	*hubBroker
	perRecipientOverride map[string]map[int]any
}

func (b *equivocatingBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From != nil && msg.From.Index == b.partyIdx && msg.To == nil {
		if override, ok := b.perRecipientOverride[msg.Type]; ok {
			for j, broker := range b.hub.brokers {
				if j == b.partyIdx {
					continue
				}
				mutated := *msg
				if alt, ok := override[j]; ok {
					mutated.Data = alt
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

// TestKeygenPartyEchoBroadcastCatchesEquivocation injects an
// application-level equivocation by the dealer at partyIdx=0: the
// broker delivers different VSS commitments to recipient 1 than to
// recipients 2/3. The echo phase MUST surface this as a tss.Error
// whose Culprits() identifies party 0.
func TestKeygenPartyEchoBroadcastCatchesEquivocation(t *testing.T) {
	const partyCount, threshold = 4, 2
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)

	// Build an alternative valid keygenR1Bcast for the dealer using a
	// distinct polynomial. The override delivers this to recipient 1
	// while recipients 2 and 3 receive the dealer's canonical bcast.
	ec := tss.S256()
	ids := pIDs.Keys()
	altU, err := rand.Int(rand.Reader, ec.Params().N)
	require.NoError(t, err)
	altVs, _, err := vss.Create(ec, threshold, altU, ids, rand.Reader)
	require.NoError(t, err)
	altBcast := &keygenR1Bcast{VSSCommitments: flattenPointXY(altVs)}

	hub.brokers[0] = (&equivocatingBroker{
		hubBroker: hub.brokers[0],
		perRecipientOverride: map[string]map[int]any{
			keygenTypeR1Bcast: {1: altBcast},
		},
	}).hubBroker
	// Swap the actual handler so the wrapper is reachable.
	eqb := &equivocatingBroker{
		hubBroker: hub.brokers[0],
		perRecipientOverride: map[string]map[int]any{
			keygenTypeR1Bcast: {1: altBcast},
		},
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*KeygenParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		if i == 0 {
			params.SetBroker(eqb)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		parties[i] = kg
	}

	// Every party must either abort (surfacing the equivocation) or
	// complete. Of the parties that abort with a tss.Error, AT LEAST
	// ONE honest recipient (parties 1..N-1) must name the equivocator
	// (party 0) as culprit. Party 0 itself, if it aborts, would name
	// the lying echoer from its own skewed perspective — that's a
	// correct local conclusion that we do not assert against.
	abortCount := 0
	namedDealer0 := 0
	dealer0Key := pIDs[0].KeyInt().String()
	for i, p := range parties {
		select {
		case <-p.Done:
			t.Logf("party %d completed (no abort surfaced)", i)
		case err := <-p.Err:
			require.Error(t, err)
			abortCount++
			tssErr, ok := err.(*tss.Error)
			if !ok {
				t.Logf("party %d error (non-tss.Error): %v", i, err)
				continue
			}
			culps := tssErr.Culprits()
			require.NotEmpty(t, culps, "party %d's tss.Error should carry a culprit", i)
			if i != 0 && culps[0].KeyInt().String() == dealer0Key {
				namedDealer0++
			}
			t.Logf("party %d aborted with culprit %s", i, culps[0].KeyInt().String())
		case <-time.After(5 * time.Minute):
			t.Fatalf("party %d neither completed nor aborted", i)
		}
	}
	require.GreaterOrEqual(t, namedDealer0, 1,
		"at least one honest recipient must identify the equivocating dealer (party 0)")
	t.Logf("equivocation aborts: %d/%d; %d honest peers named dealer 0", abortCount, partyCount, namedDealer0)
}

// TestRefreshPartyEchoBroadcastCatchesEquivocation: at refresh time
// party 0 (the equivocating dealer) ships different
// zero-constant-term commitments to recipient 1 than to recipients
// 2/3. The NEW-side echo phase must surface the disagreement with
// party 0 named as culprit on every honest recipient.
func TestRefreshPartyEchoBroadcastCatchesEquivocation(t *testing.T) {
	const partyCount, threshold = 4, 2
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	oldKeys := runDistributedKeygen(t, pIDs, threshold)

	hub := newTestHub(partyCount)

	// Alternative refresh-Vs (zero-constant polynomial, threshold
	// coefficients). vss.Create won't help — it always emits the
	// constant term too. Build manually like refresh_party.go round1.
	ec := tss.S256()
	q := ec.Params().N
	coeffs := make([]*big.Int, threshold)
	altVs := make([]*crypto.ECPoint, threshold)
	for k := 0; k < threshold; k++ {
		c, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)
		coeffs[k] = c
		altVs[k] = crypto.ScalarBaseMult(ec, c)
	}
	altBcast := &refreshR1Bcast{VSSCommitments: flattenPointXY(altVs)}

	eqb := &equivocatingBroker{
		hubBroker: hub.brokers[0],
		perRecipientOverride: map[string]map[int]any{
			refreshTypeR1Bcast: {1: altBcast},
		},
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*RefreshParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		if i == 0 {
			params.SetBroker(eqb)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		rp, err := NewRefresh(context.Background(), params, oldKeys[i])
		require.NoError(t, err)
		parties[i] = rp
	}

	dealer0Key := pIDs[0].KeyInt().String()
	namedDealer0 := 0
	for i, p := range parties {
		select {
		case <-p.Done:
			t.Logf("party %d completed", i)
		case err := <-p.Err:
			require.Error(t, err)
			tssErr, ok := err.(*tss.Error)
			if !ok {
				t.Logf("party %d non-tss.Error: %v", i, err)
				continue
			}
			culps := tssErr.Culprits()
			require.NotEmpty(t, culps, "party %d's tss.Error should carry a culprit", i)
			if i != 0 && culps[0].KeyInt().String() == dealer0Key {
				namedDealer0++
			}
			t.Logf("party %d aborted with culprit %s", i, culps[0].KeyInt().String())
		case <-time.After(5 * time.Minute):
			t.Fatalf("party %d neither completed nor aborted", i)
		}
	}
	require.GreaterOrEqual(t, namedDealer0, 1,
		"at least one honest recipient must identify the equivocating dealer (party 0)")
}

// TestResharingPartyEchoBroadcastCatchesEquivocation: OLD participant 0
// ships different commitments to NEW members. NEW-side echo phase
// must surface the abort with OLD party 0 named as culprit.
func TestResharingPartyEchoBroadcastCatchesEquivocation(t *testing.T) {
	const oldN, oldT = 3, 1
	oldPIDs := tss.GenerateTestPartyIDs(oldN)
	oldKeys := runDistributedKeygen(t, oldPIDs, oldT)
	oldPub := oldKeys[0].ECDSAPub

	newPIDs := genPartyIDsOffset(3, 12000)
	const newT = 1
	oldSubset := tss.SortedPartyIDs{oldPIDs[0], oldPIDs[1]}

	combined := append(tss.UnSortedPartyIDs(nil), oldPIDs...)
	combined = append(combined, newPIDs...)
	combinedSorted := tss.SortPartyIDs(combined)
	combinedCtx := tss.NewPeerContext(combinedSorted)

	hub := newTestHub(len(combinedSorted))
	pidIdx := map[string]int{}
	for i, p := range combinedSorted {
		pidIdx[p.KeyInt().String()] = i
	}

	// Build an alternative valid reshareR1Bcast for OLD party 0 (a
	// different polynomial over the new committee).
	ec := tss.S256()
	q := ec.Params().N
	newIDs := newPIDs.Keys()
	altScaled, err := rand.Int(rand.Reader, q)
	require.NoError(t, err)
	altVs, _, err := vss.Create(ec, newT, altScaled, newIDs, rand.Reader)
	require.NoError(t, err)
	altBcast := &reshareR1Bcast{VSSCommitments: flattenPointXY(altVs)}

	old0Idx := pidIdx[oldPIDs[0].KeyInt().String()]
	new1Idx := pidIdx[newPIDs[1].KeyInt().String()]

	eqb := &equivocatingBroker{
		hubBroker: hub.brokers[old0Idx],
		perRecipientOverride: map[string]map[int]any{
			reshareTypeR1Bcast: {new1Idx: altBcast},
		},
	}

	// Spawn OLD parties.
	for _, p := range oldSubset {
		oldIdxKey := -1
		for j, q := range oldPIDs {
			if q.KeyInt().Cmp(p.KeyInt()) == 0 {
				oldIdxKey = j
				break
			}
		}
		params := tss.NewParameters(tss.S256(), combinedCtx, p, len(combinedSorted), oldT)
		if pidIdx[p.KeyInt().String()] == old0Idx {
			params.SetBroker(eqb)
		} else {
			params.SetBroker(hub.brokers[pidIdx[p.KeyInt().String()]])
		}
		_, err := NewResharing(context.Background(), params, oldPub, oldKeys[oldIdxKey], oldSubset, newPIDs, newT)
		require.NoError(t, err)
	}

	// Spawn NEW parties.
	var newParties []*ResharingParty
	for _, p := range newPIDs {
		params := tss.NewParameters(tss.S256(), combinedCtx, p, len(combinedSorted), newT)
		params.SetBroker(hub.brokers[pidIdx[p.KeyInt().String()]])
		rp, err := NewResharing(context.Background(), params, oldPub, nil, oldSubset, newPIDs, newT)
		require.NoError(t, err)
		newParties = append(newParties, rp)
	}

	dealer0Key := oldPIDs[0].KeyInt().String()
	namedDealer0 := 0
	for i, p := range newParties {
		select {
		case k := <-p.Done:
			t.Logf("new party %d completed (key non-nil: %v)", i, k != nil)
		case err := <-p.Err:
			require.Error(t, err)
			tssErr, ok := err.(*tss.Error)
			if !ok {
				t.Logf("new party %d non-tss.Error: %v", i, err)
				continue
			}
			culps := tssErr.Culprits()
			require.NotEmpty(t, culps)
			if culps[0].KeyInt().String() == dealer0Key {
				namedDealer0++
			}
			t.Logf("new party %d aborted, culprit=%s", i, culps[0].KeyInt().String())
		case <-time.After(5 * time.Minute):
			t.Fatalf("new party %d neither completed nor aborted", i)
		}
	}
	require.GreaterOrEqual(t, namedDealer0, 1,
		"at least one new party must identify OLD party 0 as the equivocator")
}

// TestSignWithPresignRejectsUnaggregatedOutput covers the H-1 audit fix:
// the PresignOutput returned by the broker-driven PresignParty holds
// only the local party's share. Feeding it into SignWithPresign in the
// pre-fix code computed φ over a single signer's share and emitted a
// non-verifying signature with no warning. The new check refuses such
// inputs explicitly so the misuse cannot land in production silently.
func TestSignWithPresignRejectsUnaggregatedOutput(t *testing.T) {
	const partyCount, threshold = 2, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)
	outs := runDistributedPresign(t, keys, pIDs, []int{0, 1})
	require.NotEmpty(t, outs)

	msg := sha256.Sum256([]byte("unaggregated should fail"))
	_, err := SignWithPresign(outs[0], msg[:], nil)
	require.Error(t, err, "per-party PresignOutput must not silently produce a signature")
	assert.Contains(t, err.Error(), "aggregated")

	// The CAS must NOT have flipped — the per-party share is still
	// available to a future online-sign protocol.
	assert.False(t, outs[0].Consumed(), "rejected call must not mark the per-party share consumed")
}

// TestSignWithPresignDurableRejectsUnaggregatedOutput is the durable
// variant of the above; the unaggregated check must fire BEFORE the
// store records the R-hash so a misuse doesn't permanently burn a
// presign record on a presign that cannot actually sign.
func TestSignWithPresignDurableRejectsUnaggregatedOutput(t *testing.T) {
	const partyCount, threshold = 2, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)
	outs := runDistributedPresign(t, keys, pIDs, []int{0, 1})
	require.NotEmpty(t, outs)

	store := NewInMemoryPresignStore()
	msg := sha256.Sum256([]byte("unaggregated durable should fail"))
	_, err := SignWithPresignDurable(outs[0], msg[:], nil, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aggregated")

	// Store must NOT have recorded the R-hash.
	recorded, err := store.CheckAndRecord(outs[0].RHash())
	require.NoError(t, err)
	assert.True(t, recorded, "store must not have recorded the R-hash on the rejected call")
}

// TestKeygenPartyAllPartiesAgreeOnBigXj covers the H-3 audit fix:
// after a distributed DKG, every party must hold the SAME BigXj table
// (which is a function of every dealer's VSS commitments). Equivocation
// — different commitments shipped to different recipients — would
// produce divergent BigXj across parties. With the post-fix protocol
// the VSS commitments travel via a To==nil broadcast whose contract
// is identical-bytes-to-every-peer, so equivocation at the dealer
// level is impossible in honest-broker deployments. The test broker
// implements that contract by reference-sharing the same *JsonMessage.
func TestKeygenPartyAllPartiesAgreeOnBigXj(t *testing.T) {
	const partyCount, threshold = 4, 2
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	keys := runDistributedKeygen(t, pIDs, threshold)
	require.Len(t, keys, partyCount)

	ref := keys[0].BigXj
	for i := 1; i < partyCount; i++ {
		require.Equalf(t, len(ref), len(keys[i].BigXj), "party %d BigXj length mismatch", i)
		for j := range ref {
			assert.Truef(t, ref[j].Equals(keys[i].BigXj[j]),
				"party %d BigXj[%d] differs from party 0 — equivocation defense regression?", i, j)
		}
		assert.Truef(t, ref[0].Curve() != nil, "party 0 BigXj[0] missing curve")
		assert.Truef(t, keys[i].ECDSAPub.Equals(keys[0].ECDSAPub),
			"party %d ECDSAPub differs from party 0", i)
	}
}
