package dklstss

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ResharingParty is the broker-driven equivalent of the synchronous
// Reshare(). Each participating party constructs its own
// *ResharingParty; the protocol routes messages via params.Broker().
//
// Roles:
//
//   - OLD participants (in the old-committee subset that resharing) run
//     round 1: they send VSS commitments + share to every new
//     committee member. After round 1 they have nothing more to do;
//     Done receives nil to signal completion.
//
//   - NEW committee members receive round-1 shares from each old
//     participant, verify, and then set up fresh pairwise OT among
//     themselves (the same two-round dance as KeygenParty). Done
//     receives the new Key on success.
//
// Disjoint vs. overlapping committees: both are supported. A party
// that appears in BOTH committees plays both roles (run two separate
// *ResharingParty instances against the same broker).
type ResharingParty struct {
	ctx    context.Context
	params *tss.Parameters

	// oldECDSAPub is the public key of the committee being resharded.
	// Every party (OLD, NEW, OLD+NEW) must agree on this value out of
	// band so:
	//   - all parties compute the same ssid for the base-OT setup that
	//     follows (fixes the H-2 partial-overlap mismatch where hybrids
	//     had oldKey and NEW-only parties didn't);
	//   - the new committee can reject a malicious OLD participant who
	//     ships VSS shares whose sum reconstructs to a different pub
	//     (fixes C-1: without this binding, a single OLD party could
	//     rotate the joint key to any value of their choosing).
	oldECDSAPub *crypto.ECPoint

	// OLD role.
	isOld         bool
	oldKey        *Key
	oldSubset     tss.SortedPartyIDs // participating old members (incl. self if isOld)
	oldLambda     *big.Int

	// NEW role.
	isNew        bool
	newSubset    tss.SortedPartyIDs
	newThreshold int
	myNewIdx     int // self index in newSubset, -1 if not NEW

	ssid []byte

	// NEW-side accumulators.
	receivedShares  map[string]*big.Int     // by old participant key
	receivedCommits map[string]vss.Vs       // by old participant key
	newOTSnd        map[string]*baseot.Sender
	newOTRcv        map[string]*baseot.Receiver
	myDelta         map[string][]byte

	// Round-1 join state on the NEW side. OLD participants now ship
	// their VSS commitments as a To==nil broadcast (so equivocation
	// is closed at the broker layer) and the per-recipient share as a
	// unicast. The echo phase cannot run until both halves arrive from
	// every OLD participant; the atomic counter goes 0 → 1 → 2 and the
	// goroutine that reaches 2 fires the echo phase.
	r1JoinCount atomic.Int32
	r1Bcasts    []*reshareR1Bcast
	r1Unicasts  []*reshareR1Unicast
	r1OldIds    []*tss.PartyID

	// Echo phase: every NEW-side party broadcasts H(V_D) digests for
	// each OLD dealer D to every other NEW-side party. A digest
	// mismatch identifies the equivocating OLD dealer (see echo.go).
	// OLD-only parties skip this phase entirely.
	r1Echoes []*echoMsg

	// oldVs holds this party's own VSS commitments (computed in
	// oldRound1). Used during the NEW-side echo verification when the
	// party is OLD+NEW hybrid: the verifier needs a canonical view of
	// its own commitments to attribute disagreement to a lying echoer
	// rather than to a (self-)equivocating dealer. Nil for NEW-only
	// parties.
	oldVs []*crypto.ECPoint

	Done chan *Key
	Err  chan error

	// Once-guards on Done/Err — see once_send.go. Resharing has the
	// extra complication of an OLD-only branch that delivers a nil
	// sentinel on Done; sendOnce handles that path the same way.
	doneOnce sync.Once
	errOnce  sync.Once
}

// NewResharing constructs a per-party reshare state machine. The
// caller's role is inferred from the membership of params.PartyID():
//
//   - If self is in oldSubset, this party plays OLD (and must supply
//     oldKey).
//   - If self is in newSubset, this party plays NEW.
//
// One or both roles must be set; otherwise the call returns an error.
//
// oldECDSAPub is the public key of the committee being resharded. It
// must be supplied to every party — OLD participants normally pass
// oldKey.ECDSAPub; NEW-only participants must learn it out of band
// (typically from the same channel that delivers oldSubset). This
// binding is the SECURITY hinge of the protocol: without it a single
// malicious OLD participant can rotate the joint key to any pub of
// their choosing, and NEW-only parties have no local way to detect it.
//
// oldKey may be nil for parties that are only NEW. oldSubset must
// contain at least oldKey.T+1 distinct members (the active subset),
// and lagrange coefficients are computed across those members.
//
// The full peer context (params.Parties()) must include both
// committees; the broker will route messages by PartyID.
func NewResharing(
	ctx context.Context,
	params *tss.Parameters,
	oldECDSAPub *crypto.ECPoint,
	oldKey *Key,
	oldSubset tss.SortedPartyIDs,
	newSubset tss.SortedPartyIDs,
	newThreshold int,
) (*ResharingParty, error) {
	if ctx == nil || params == nil {
		return nil, errors.New("dklstss: NewResharing nil argument")
	}
	if oldECDSAPub == nil || !oldECDSAPub.ValidateBasic() {
		return nil, errors.New("dklstss: NewResharing requires oldECDSAPub (the public key being resharded) to be a valid curve point")
	}
	if !tss.SameCurve(params.EC(), tss.S256()) {
		return nil, errors.New("dklstss: NewResharing requires secp256k1")
	}
	self := params.PartyID()
	isOld := false
	for _, p := range oldSubset {
		if p.KeyInt().Cmp(self.KeyInt()) == 0 {
			isOld = true
			break
		}
	}
	myNewIdx := -1
	for i, p := range newSubset {
		if p.KeyInt().Cmp(self.KeyInt()) == 0 {
			myNewIdx = i
			break
		}
	}
	isNew := myNewIdx >= 0

	if !isOld && !isNew {
		return nil, errors.New("dklstss: NewResharing self is in neither committee")
	}
	if isOld && oldKey == nil {
		return nil, errors.New("dklstss: NewResharing oldKey required for OLD role")
	}
	if isOld {
		if err := oldKey.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("dklstss: NewResharing invalid oldKey: %w", err)
		}
		if len(oldSubset) < oldKey.T+1 {
			return nil, fmt.Errorf("dklstss: NewResharing oldSubset size %d < T+1=%d", len(oldSubset), oldKey.T+1)
		}
		if !oldECDSAPub.Equals(oldKey.ECDSAPub) {
			// Catch caller bugs where oldECDSAPub was passed in
			// inconsistent with the OLD party's local oldKey. The
			// security hinge depends on oldECDSAPub being correct;
			// fail loudly rather than proceed with a mismatched view.
			return nil, errors.New("dklstss: NewResharing oldECDSAPub does not match oldKey.ECDSAPub")
		}
	}
	if isNew {
		if newThreshold < 1 || newThreshold >= len(newSubset) {
			return nil, fmt.Errorf("dklstss: NewResharing invalid newThreshold %d (need 1..%d)", newThreshold, len(newSubset)-1)
		}
	}

	rp := &ResharingParty{
		ctx:             ctx,
		params:          params,
		oldECDSAPub:     oldECDSAPub,
		isOld:           isOld,
		oldKey:          oldKey,
		oldSubset:       oldSubset,
		isNew:           isNew,
		newSubset:       newSubset,
		newThreshold:    newThreshold,
		myNewIdx:        myNewIdx,
		ssid:            resharingSession(params, oldECDSAPub, oldSubset, newSubset, newThreshold),
		receivedShares:  make(map[string]*big.Int),
		receivedCommits: make(map[string]vss.Vs),
		newOTSnd:        make(map[string]*baseot.Sender),
		newOTRcv:        make(map[string]*baseot.Receiver),
		myDelta:         make(map[string][]byte),
		Done:            make(chan *Key, 1),
		Err:             make(chan error, 1),
	}

	// OLD-side: pre-compute Lagrange coefficient.
	if isOld {
		q := params.EC().Params().N
		oldIDs := make([]*big.Int, len(oldSubset))
		for i, p := range oldSubset {
			oldIDs[i] = p.KeyInt()
		}
		myOldSubsetIdx := -1
		for i, p := range oldSubset {
			if p.KeyInt().Cmp(self.KeyInt()) == 0 {
				myOldSubsetIdx = i
				break
			}
		}
		lam, err := lagrangeCoefficient(q, oldIDs, myOldSubsetIdx)
		if err != nil {
			return nil, fmt.Errorf("dklstss: NewResharing lagrange: %w", err)
		}
		rp.oldLambda = lam
	}

	// Register NEW-side receivers first (so messages aren't dropped).
	if isNew {
		rp.r1OldIds = []*tss.PartyID(oldSubset)
		rcvBcast := tss.NewJsonExpect[reshareR1Bcast](reshareTypeR1Bcast, rp.r1OldIds, rp.onR1Bcast)
		rcvUnicast := tss.NewJsonExpect[reshareR1Unicast](reshareTypeR1Unicast, rp.r1OldIds, rp.onR1Unicast)
		params.Broker().Connect(reshareTypeR1Bcast, rcvBcast)
		params.Broker().Connect(reshareTypeR1Unicast, rcvUnicast)
	}

	// OLD-side: kick off round 1 immediately.
	if isOld {
		if err := rp.oldRound1(); err != nil {
			return nil, fmt.Errorf("dklstss: NewResharing oldRound1: %w", err)
		}
	}

	// If the local party is ONLY new (not old), it just waits for
	// messages. Done gets fired by finalize().
	// If the local party is ONLY old, signal completion immediately
	// via a non-nil sentinel (Done will fire after round 1 emits).
	// We don't have a separate signal for OLD completion right now;
	// callers that are OLD-only treat returning from NewResharing
	// (after round 1 broadcasts) as "done with the protocol".
	return rp, nil
}

// oldRound1 sends VSS commitments to the scaled old share + per-recipient
// shares to every new committee member.
func (rp *ResharingParty) oldRound1() error {
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	q := ec.Params().N

	// Scaled secret = λ_i · oldKey.Xi mod q.
	scaled := new(big.Int).Mul(rp.oldLambda, rp.oldKey.Xi)
	scaled.Mod(scaled, q)
	if scaled.Sign() == 0 {
		// See resharing.go for rationale: probability ~ 1/q. Treat as
		// fatal rather than silently substituting a non-zero scalar
		// (which would mint an unrelated public key downstream).
		return fmt.Errorf("dklstss: oldKey λ·Xi ≡ 0 mod q (key material likely corrupted)")
	}

	newIDs := make([]*big.Int, len(rp.newSubset))
	for i, p := range rp.newSubset {
		newIDs[i] = p.KeyInt()
	}
	if _, err := vss.CheckIndexes(ec, newIDs); err != nil {
		return fmt.Errorf("invalid new committee IDs: %w", err)
	}

	Vs, shares, err := vss.Create(ec, rp.newThreshold, scaled, newIDs, rp.params.Rand())
	if err != nil {
		return fmt.Errorf("vss.Create: %w", err)
	}
	encVs := flattenPointXY(Vs)
	rp.oldVs = Vs

	// BROADCAST: Vs commitments. Identical bytes for every recipient,
	// sent via To==nil so the broker contract gives the NEW committee
	// a single canonical view per OLD party (closes the equivocation
	// hole H-3 also called out in the audit). The broker contract is
	// the same as for keygen_party — see that file for the rationale.
	bcast := &reshareR1Bcast{VSSCommitments: encVs}
	bm := tss.JsonWrap(reshareTypeR1Bcast, bcast, Pi, nil)
	if err := rp.params.Broker().Receive(bm); err != nil {
		return fmt.Errorf("broker r1-bcast: %w", err)
	}

	// UNICAST: per-recipient share (peer-specific).
	for n, Pj := range rp.newSubset {
		uc := &reshareR1Unicast{Share: shares[n].Share.Bytes()}
		m := tss.JsonWrap(reshareTypeR1Unicast, uc, Pi, Pj)
		if err := rp.params.Broker().Receive(m); err != nil {
			return fmt.Errorf("broker r1-uc→%s: %w", Pj, err)
		}
	}
	// Old-only parties also signal completion now.
	if !rp.isNew {
		sendOnce(&rp.doneOnce, rp.Done, nil)
	}
	return nil
}

// onR1Bcast / onR1Unicast: NEW-side join of round 1. See keygen_party.go
// for the broker-contract rationale. The second-to-complete callback
// fires the echo phase, which gates afterRound1 on a cryptographic
// agreement among NEW-side parties about every OLD dealer's
// commitments.
func (rp *ResharingParty) onR1Bcast(oldIds []*tss.PartyID, msgs []*reshareR1Bcast) {
	rp.r1Bcasts = msgs
	if rp.r1JoinCount.Add(1) == 2 {
		rp.startEchoPhase(oldIds)
	}
}

func (rp *ResharingParty) onR1Unicast(oldIds []*tss.PartyID, msgs []*reshareR1Unicast) {
	rp.r1Unicasts = msgs
	if rp.r1JoinCount.Add(1) == 2 {
		rp.startEchoPhase(oldIds)
	}
}

// startEchoPhase: every NEW-side party broadcasts digests of every OLD
// dealer's commitments to every OTHER NEW-side party. See
// keygen_party.go for the rationale; the reshare variant differs in
// that dealers (OLD) and echoers (NEW) are not the same set.
//
// OLD-only parties never reach this method — they finish after
// oldRound1.
func (rp *ResharingParty) startEchoPhase(oldIds []*tss.PartyID) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	Pi := rp.params.PartyID()
	selfKey := peerKeyStr(Pi)

	digests := make(map[string][]byte, len(oldIds))
	for n, dealer := range oldIds {
		dealerKey := peerKeyStr(dealer)
		if dealerKey == selfKey {
			// OLD+NEW hybrid: don't echo about my own commitments.
			// Other echoers carry the relevant cross-check for me.
			continue
		}
		digests[dealerKey] = commitDigest(echoTagReshare, dealer, rp.r1Bcasts[n].VSSCommitments)
	}

	newOthers := make([]*tss.PartyID, 0, len(rp.newSubset)-1)
	for _, p := range rp.newSubset {
		if p.KeyInt().Cmp(Pi.KeyInt()) != 0 {
			newOthers = append(newOthers, p)
		}
	}

	out := &echoMsg{Digests: digests}
	m := tss.JsonWrap(reshareTypeEcho, out, Pi, nil)
	if err := rp.params.Broker().Receive(m); err != nil {
		sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("broker echo broadcast: %w", err))
		return
	}
	rcv := tss.NewJsonExpect[echoMsg](reshareTypeEcho, newOthers, func(eids []*tss.PartyID, msgs []*echoMsg) {
		rp.onEcho(oldIds, eids, msgs)
	})
	rp.params.Broker().Connect(reshareTypeEcho, rcv)
}

// onEcho cross-checks NEW-side echoes against the local view of each
// OLD dealer's commitments. On consistency, fires afterRound1.
func (rp *ResharingParty) onEcho(oldIds []*tss.PartyID, echoers []*tss.PartyID, msgs []*echoMsg) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	Pi := rp.params.PartyID()
	selfKey := peerKeyStr(Pi)

	myDigests := make(map[string][]byte, len(oldIds))
	for n, dealer := range oldIds {
		dealerKey := peerKeyStr(dealer)
		if dealerKey == selfKey {
			// OLD+NEW hybrid: canonical view of own commitments, used
			// to attribute disagreement to a lying echoer rather than
			// to a (self-)equivocating dealer.
			if rp.oldVs != nil {
				myDigests[selfKey] = commitDigest(echoTagReshare, dealer, flattenPointXY(rp.oldVs))
			}
			continue
		}
		myDigests[dealerKey] = commitDigest(echoTagReshare, dealer, rp.r1Bcasts[n].VSSCommitments)
	}

	if err := verifyEchoes(myDigests, selfKey, echoers, msgs, oldIds, echoSourceReshare); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	rp.r1Echoes = msgs
	rp.afterRound1(oldIds)
}

// afterRound1 fires on the NEW side once shares from every old subset
// member have arrived. Verify, aggregate Xi, kick off pairwise OT.
func (rp *ResharingParty) afterRound1(oldIds []*tss.PartyID) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	q := ec.Params().N
	bcasts := rp.r1Bcasts
	ucs := rp.r1Unicasts

	// Verify shares + collect commitments.
	for n, pid := range oldIds {
		bc := bcasts[n]
		uc := ucs[n]
		if len(bc.VSSCommitments) != 2*(rp.newThreshold+1) {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s sent %d Vs coords, expected %d",
				pid, len(bc.VSSCommitments), 2*(rp.newThreshold+1)))
			return
		}
		vsj, err := unflattenPointXY(ec, bc.VSSCommitments)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s Vs decode: %w", pid, err))
			return
		}
		shareInt := new(big.Int).SetBytes(uc.Share)
		// Reject non-canonical (>= q) shares — see keygen_party round2
		// for the rationale (echo-bypass via non-canonical bytes).
		if shareInt.Sign() < 0 || shareInt.Cmp(q) >= 0 {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s sent non-canonical reshare-share (>= q)", pid))
			return
		}
		sh := &vss.Share{Threshold: rp.newThreshold, ID: Pi.KeyInt(), Share: shareInt}
		if !sh.Verify(ec, rp.newThreshold, vsj) {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s reshare-share verification failed", pid))
			return
		}
		rp.receivedShares[peerKeyStr(pid)] = shareInt
		rp.receivedCommits[peerKeyStr(pid)] = vsj
	}

	// Compute new local share x_i = Σ shares from old participants.
	newXi := new(big.Int)
	for _, sh := range rp.receivedShares {
		newXi.Add(newXi, sh)
		newXi.Mod(newXi, q)
	}

	// Kick off pairwise OT setup with the OTHER new committee members.
	newOthers := make([]*tss.PartyID, 0, len(rp.newSubset)-1)
	for _, p := range rp.newSubset {
		if p.KeyInt().Cmp(Pi.KeyInt()) != 0 {
			newOthers = append(newOthers, p)
		}
	}

	// Send base-OT Sender msgs to every new peer.
	for _, Pj := range newOthers {
		sid := pairBaseSid(rp.ssid, Pi.KeyInt(), Pj.KeyInt(), Pj.KeyInt())
		snd, sndMsg, err := baseot.NewSender(sid, otext.Kappa, rp.params.Rand())
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("baseot.NewSender for %s: %w", Pj, err))
			return
		}
		rp.newOTSnd[peerKeyStr(Pj)] = snd

		r2 := &reshareR2{
			OTSenderSX:    sndMsg.S.X().Bytes(),
			OTSenderSY:    sndMsg.S.Y().Bytes(),
			OTSenderPokAX: sndMsg.PoK.Alpha.X().Bytes(),
			OTSenderPokAY: sndMsg.PoK.Alpha.Y().Bytes(),
			OTSenderPokT:  sndMsg.PoK.T.Bytes(),
		}
		m := tss.JsonWrap(reshareTypeR2, r2, Pi, Pj)
		if err := rp.params.Broker().Receive(m); err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("broker r2→%s: %w", Pj, err))
			return
		}
	}
	// Register receiver for round 2 from new peers.
	rcv := tss.NewJsonExpect[reshareR2](reshareTypeR2, newOthers,
		func(ids []*tss.PartyID, m []*reshareR2) {
			rp.afterRound2(ids, m, newXi, newOthers)
		})
	rp.params.Broker().Connect(reshareTypeR2, rcv)
}

func (rp *ResharingParty) afterRound2(newOthersFromCB []*tss.PartyID, msgs []*reshareR2, newXi *big.Int, newOthers []*tss.PartyID) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	_ = newOthersFromCB // identical to newOthers by construction

	// Build base-OT Receiver responses for each new peer's S+PoK.
	for n, pid := range newOthers {
		r2 := msgs[n]
		Sj, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(r2.OTSenderSX),
			new(big.Int).SetBytes(r2.OTSenderSY))
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s OT-S invalid: %w", pid, err))
			return
		}
		alpha, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(r2.OTSenderPokAX),
			new(big.Int).SetBytes(r2.OTSenderPokAY))
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s PoK-alpha invalid: %w", pid, err))
			return
		}
		pok := &schnorr.ZKProof{Alpha: alpha, T: new(big.Int).SetBytes(r2.OTSenderPokT)}
		sid := pairBaseSid(rp.ssid, pid.KeyInt(), Pi.KeyInt(), Pi.KeyInt())
		sndMsg := &baseot.SenderMsg1{S: Sj, PoK: pok}

		delta := make([]byte, otext.DeltaBytes)
		if _, err := rp.params.Rand().Read(delta); err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("rand: %w", err))
			return
		}
		rcvr, rcvMsg, err := baseot.NewReceiver(sid, otext.Kappa, delta, sndMsg, rp.params.Rand())
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("base-OT receiver for %s: %w", pid, err))
			return
		}
		rp.newOTRcv[peerKeyStr(pid)] = rcvr
		rp.myDelta[peerKeyStr(pid)] = delta

		r3 := &keygenR2{OTReceiverR: flattenPointXY(rcvMsg.R)}
		m := tss.JsonWrap(reshareTypeR3, r3, Pi, pid)
		if err := rp.params.Broker().Receive(m); err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("broker r3→%s: %w", pid, err))
			return
		}
	}
	rcv := tss.NewJsonExpect[keygenR2](reshareTypeR3, newOthers,
		func(ids []*tss.PartyID, m []*keygenR2) {
			rp.finalize(ids, m, newXi, newOthers)
		})
	rp.params.Broker().Connect(reshareTypeR3, rcv)
}

func (rp *ResharingParty) finalize(_ []*tss.PartyID, msgs []*keygenR2, newXi *big.Int, newOthers []*tss.PartyID) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	n := len(rp.newSubset)

	// Reconstruct ECDSAPub from old commitments — Σ V_old_i[0] equals
	// (Σ scaled_share_i) · G = secret · G = oldECDSAPub when the OLD
	// participants act honestly. Verify this binding; a mismatch means
	// at least one OLD party shipped a polynomial whose constant term
	// is not λ_i · x_i (C-1: a malicious OLD party could otherwise
	// rotate the new committee onto an unrelated public key without any
	// other party noticing).
	var pub *crypto.ECPoint
	for _, Vs := range rp.receivedCommits {
		if pub == nil {
			pub = Vs[0]
		} else {
			next, err := pub.Add(Vs[0])
			if err != nil {
				sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("aggregate pub: %w", err))
				return
			}
			pub = next
		}
	}
	if pub == nil || !pub.Equals(rp.oldECDSAPub) {
		sendOnce(&rp.errOnce, rp.Err, errors.New("dklstss: reshare reconstructed public key does not match the advertised oldECDSAPub — at least one OLD participant shipped a malformed VSS commitment"))
		return
	}
	// From here on, downstream code uses oldECDSAPub for the new Key's
	// ECDSAPub field. The aggregated value above was only the witness.
	pub = rp.oldECDSAPub

	// BigXj[j] = sum of (Vs[k] · id_j^k) over all old participants.
	// Evaluating the summed polynomial at id_j.
	newBigXj := make([]*crypto.ECPoint, n)
	allCommits := make([]vss.Vs, 0, len(rp.receivedCommits))
	for _, c := range rp.receivedCommits {
		allCommits = append(allCommits, c)
	}
	for _, pj := range rp.newSubset {
		Xj, err := evaluateCommitmentSum(ec, allCommits, pj.KeyInt())
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("BigXj[%d]: %w", pj.Index, err))
			return
		}
		newBigXj[pj.Index] = Xj
	}

	// Pairwise OT setup → fold finalize calls.
	ot := make([]*PairOTState, n)
	for _, pj := range newOthers {
		peerk := peerKeyStr(pj)
		chosen, err := rp.newOTRcv[peerk].Finalize()
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("base-OT receiver finalize for %s: %w", pj, err))
			return
		}
		extSender, err := otext.NewExtSenderFromBase(rp.myDelta[peerk], chosen)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("ExtSender for %s: %w", pj, err))
			return
		}
		var r3 *keygenR2
		for idx, pid := range newOthers {
			if pid.KeyInt().Cmp(pj.KeyInt()) == 0 {
				r3 = msgs[idx]
				break
			}
		}
		if r3 == nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("missing r3 from %s", pj))
			return
		}
		rPoints, err := unflattenPointXY(ec, r3.OTReceiverR)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("decode R from %s: %w", pj, err))
			return
		}
		k0, k1, err := rp.newOTSnd[peerk].Finalize(&baseot.ReceiverMsg1{R: rPoints})
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("base-OT sender finalize for %s: %w", pj, err))
			return
		}
		extReceiver, err := otext.NewExtReceiverFromBase(k0, k1)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("ExtReceiver for %s: %w", pj, err))
			return
		}
		ot[pj.Index] = &PairOTState{AsAlice: extReceiver, AsBob: extSender}
	}

	chainCode := deriveChainCode(pub)
	key := &Key{
		Curve:     ec,
		N:         n,
		T:         rp.newThreshold,
		Idx:       rp.myNewIdx,
		PartyIDs:  rp.newSubset,
		Xi:        newXi,
		BigXj:     newBigXj,
		ECDSAPub:  pub,
		OT:        ot,
		ChainCode: chainCode,
	}
	if err := key.ValidateBasic(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("finalize ValidateBasic: %w", err))
		return
	}
	_ = Pi
	_ = common.RejectionSample // keep import live across edits
	sendOnce(&rp.doneOnce, rp.Done, key)
}

// reshareR1Bcast is the OLD→NEW round-1 BROADCAST: Vs commitments
// (same bytes for every recipient). Sent via To==nil to close the
// equivocation hole: a malicious OLD party cannot ship different
// commitments to different NEW members under the broker contract.
type reshareR1Bcast struct {
	VSSCommitments [][]byte `json:"vss_commitments"`
}

// reshareR1Unicast is the OLD→NEW round-1 UNICAST half: the
// per-recipient share evaluated at the recipient's id.
type reshareR1Unicast struct {
	Share []byte `json:"share"`
}

// reshareR2 is a new-committee party's base-OT-Sender message to a peer.
type reshareR2 struct {
	OTSenderSX    []byte `json:"ot_sender_s_x"`
	OTSenderSY    []byte `json:"ot_sender_s_y"`
	OTSenderPokAX []byte `json:"ot_sender_pok_alpha_x"`
	OTSenderPokAY []byte `json:"ot_sender_pok_alpha_y"`
	OTSenderPokT  []byte `json:"ot_sender_pok_t"`
}

const (
	reshareTypeR1Bcast   = "dkls:reshare:r1bc" // OLD → NEW (broadcast): Vs
	reshareTypeR1Unicast = "dkls:reshare:r1uc" // OLD → NEW (unicast): share
	reshareTypeEcho      = "dkls:reshare:echo" // NEW → NEW (broadcast): commitment digests
	reshareTypeR2        = "dkls:reshare:r2"   // NEW → NEW: base-OT-Sender
	reshareTypeR3        = "dkls:reshare:r3"   // NEW → NEW: base-OT-Receiver-R

	echoTagReshare    = "DKLS23-echo-reshare-v1"
	echoSourceReshare = "dklstss-reshare"
)

func resharingSession(params *tss.Parameters, oldECDSAPub *crypto.ECPoint, oldSubset, newSubset tss.SortedPartyIDs, newThreshold int) []byte {
	// As with refreshSession, the resharing protocol only runs base-OT
	// setup (no signing-time ΠMul), so even if two resharings produce
	// the same ssid the resulting OT-extension seeds differ due to
	// fresh internal randomness in base-OT. Encoding newThreshold as
	// big-endian 4 bytes (was byte()) so values >= 256 cannot collide.
	//
	// oldECDSAPub is unconditional here — every party (OLD, NEW,
	// OLD+NEW) must supply it via the NewResharing parameter, which is
	// what closes the partial-overlap mismatch flagged by H-2. The
	// constructor refuses nil oldECDSAPub.
	h := sha256.New()
	h.Write([]byte("DKLS23-reshare-party-v2-"))
	h.Write(oldECDSAPub.X().Bytes())
	h.Write([]byte{'|'})
	h.Write(oldECDSAPub.Y().Bytes())
	h.Write([]byte{'|'})
	for _, p := range oldSubset {
		h.Write(p.KeyInt().Bytes())
		h.Write([]byte{0})
	}
	h.Write([]byte{'|'})
	for _, p := range newSubset {
		h.Write(p.KeyInt().Bytes())
		h.Write([]byte{0})
	}
	var buf [4]byte
	buf[0] = byte(newThreshold >> 24)
	buf[1] = byte(newThreshold >> 16)
	buf[2] = byte(newThreshold >> 8)
	buf[3] = byte(newThreshold)
	h.Write(buf[:])
	return h.Sum(nil)
}
