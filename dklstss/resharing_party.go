package dklstss

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

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

	Done chan *Key
	Err  chan error
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
// oldKey may be nil for parties that are only NEW. oldSubset must
// contain at least oldKey.T+1 distinct members (the active subset),
// and lagrange coefficients are computed across those members.
//
// The full peer context (params.Parties()) must include both
// committees; the broker will route messages by PartyID.
func NewResharing(
	ctx context.Context,
	params *tss.Parameters,
	oldKey *Key,
	oldSubset tss.SortedPartyIDs,
	newSubset tss.SortedPartyIDs,
	newThreshold int,
) (*ResharingParty, error) {
	if ctx == nil || params == nil {
		return nil, errors.New("dklstss: NewResharing nil argument")
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
	}
	if isNew {
		if newThreshold < 1 || newThreshold >= len(newSubset) {
			return nil, fmt.Errorf("dklstss: NewResharing invalid newThreshold %d (need 1..%d)", newThreshold, len(newSubset)-1)
		}
	}

	rp := &ResharingParty{
		ctx:             ctx,
		params:          params,
		isOld:           isOld,
		oldKey:          oldKey,
		oldSubset:       oldSubset,
		isNew:           isNew,
		newSubset:       newSubset,
		newThreshold:    newThreshold,
		myNewIdx:        myNewIdx,
		ssid:            resharingSession(params, oldKey, oldSubset, newSubset, newThreshold),
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
		// Round 1 expects shares from EVERY old subset member.
		rcv := tss.NewJsonExpect[reshareR1](reshareTypeR1, []*tss.PartyID(oldSubset), rp.afterRound1)
		params.Broker().Connect(reshareTypeR1, rcv)
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
		scaled.SetInt64(1) // vanishingly unlikely; avoids vss.Create panic
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

	for n, Pj := range rp.newSubset {
		r1 := &reshareR1{
			VSSCommitments: encVs,
			Share:          shares[n].Share.Bytes(),
		}
		m := tss.JsonWrap(reshareTypeR1, r1, Pi, Pj)
		if err := rp.params.Broker().Receive(m); err != nil {
			return fmt.Errorf("broker r1→%s: %w", Pj, err)
		}
	}
	// Old-only parties also signal completion now.
	if !rp.isNew {
		rp.Done <- nil
	}
	return nil
}

// afterRound1 fires on the NEW side once shares from every old subset
// member have arrived. Verify, aggregate Xi, kick off pairwise OT.
func (rp *ResharingParty) afterRound1(oldIds []*tss.PartyID, msgs []*reshareR1) {
	if err := rp.ctx.Err(); err != nil {
		rp.Err <- err
		return
	}
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	q := ec.Params().N

	// Verify shares + collect commitments.
	for n, pid := range oldIds {
		r1 := msgs[n]
		if len(r1.VSSCommitments) != 2*(rp.newThreshold+1) {
			rp.Err <- fmt.Errorf("party %s sent %d Vs coords, expected %d",
				pid, len(r1.VSSCommitments), 2*(rp.newThreshold+1))
			return
		}
		vsj, err := unflattenPointXY(ec, r1.VSSCommitments)
		if err != nil {
			rp.Err <- fmt.Errorf("party %s Vs decode: %w", pid, err)
			return
		}
		shareInt := new(big.Int).SetBytes(r1.Share)
		sh := &vss.Share{Threshold: rp.newThreshold, ID: Pi.KeyInt(), Share: shareInt}
		if !sh.Verify(ec, rp.newThreshold, vsj) {
			rp.Err <- fmt.Errorf("party %s reshare-share verification failed", pid)
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
			rp.Err <- fmt.Errorf("baseot.NewSender for %s: %w", Pj, err)
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
			rp.Err <- fmt.Errorf("broker r2→%s: %w", Pj, err)
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
		rp.Err <- err
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
			rp.Err <- fmt.Errorf("party %s OT-S invalid: %w", pid, err)
			return
		}
		alpha, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(r2.OTSenderPokAX),
			new(big.Int).SetBytes(r2.OTSenderPokAY))
		if err != nil {
			rp.Err <- fmt.Errorf("party %s PoK-alpha invalid: %w", pid, err)
			return
		}
		pok := &schnorr.ZKProof{Alpha: alpha, T: new(big.Int).SetBytes(r2.OTSenderPokT)}
		sid := pairBaseSid(rp.ssid, pid.KeyInt(), Pi.KeyInt(), Pi.KeyInt())
		sndMsg := &baseot.SenderMsg1{S: Sj, PoK: pok}

		delta := make([]byte, otext.DeltaBytes)
		if _, err := rp.params.Rand().Read(delta); err != nil {
			rp.Err <- fmt.Errorf("rand: %w", err)
			return
		}
		rcvr, rcvMsg, err := baseot.NewReceiver(sid, otext.Kappa, delta, sndMsg, rp.params.Rand())
		if err != nil {
			rp.Err <- fmt.Errorf("base-OT receiver for %s: %w", pid, err)
			return
		}
		rp.newOTRcv[peerKeyStr(pid)] = rcvr
		rp.myDelta[peerKeyStr(pid)] = delta

		r3 := &keygenR2{OTReceiverR: flattenPointXY(rcvMsg.R)}
		m := tss.JsonWrap(reshareTypeR3, r3, Pi, pid)
		if err := rp.params.Broker().Receive(m); err != nil {
			rp.Err <- fmt.Errorf("broker r3→%s: %w", pid, err)
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
		rp.Err <- err
		return
	}
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	n := len(rp.newSubset)

	// Reconstruct ECDSAPub from old commitments — Σ V_old_i[0] equals
	// (Σ scaled_share_i) · G = secret · G = oldKey.ECDSAPub.
	var pub *crypto.ECPoint
	for _, Vs := range rp.receivedCommits {
		if pub == nil {
			pub = Vs[0]
		} else {
			next, err := pub.Add(Vs[0])
			if err != nil {
				rp.Err <- fmt.Errorf("aggregate pub: %w", err)
				return
			}
			pub = next
		}
	}

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
			rp.Err <- fmt.Errorf("BigXj[%d]: %w", pj.Index, err)
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
			rp.Err <- fmt.Errorf("base-OT receiver finalize for %s: %w", pj, err)
			return
		}
		extSender, err := otext.NewExtSenderFromBase(rp.myDelta[peerk], chosen)
		if err != nil {
			rp.Err <- fmt.Errorf("ExtSender for %s: %w", pj, err)
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
			rp.Err <- fmt.Errorf("missing r3 from %s", pj)
			return
		}
		rPoints, err := unflattenPointXY(ec, r3.OTReceiverR)
		if err != nil {
			rp.Err <- fmt.Errorf("decode R from %s: %w", pj, err)
			return
		}
		k0, k1, err := rp.newOTSnd[peerk].Finalize(&baseot.ReceiverMsg1{R: rPoints})
		if err != nil {
			rp.Err <- fmt.Errorf("base-OT sender finalize for %s: %w", pj, err)
			return
		}
		extReceiver, err := otext.NewExtReceiverFromBase(k0, k1)
		if err != nil {
			rp.Err <- fmt.Errorf("ExtReceiver for %s: %w", pj, err)
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
		rp.Err <- fmt.Errorf("finalize ValidateBasic: %w", err)
		return
	}
	_ = Pi
	_ = common.RejectionSample // keep import live across edits
	rp.Done <- key
}

// reshareR1 carries an old participant's VSS commitments + recipient share.
type reshareR1 struct {
	VSSCommitments [][]byte `json:"vss_commitments"`
	Share          []byte   `json:"share"`
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
	reshareTypeR1 = "dkls:reshare:r1" // OLD → NEW: VSS+share
	reshareTypeR2 = "dkls:reshare:r2" // NEW → NEW: base-OT-Sender
	reshareTypeR3 = "dkls:reshare:r3" // NEW → NEW: base-OT-Receiver-R
)

func resharingSession(params *tss.Parameters, oldKey *Key, oldSubset, newSubset tss.SortedPartyIDs, newThreshold int) []byte {
	h := sha256.New()
	h.Write([]byte("DKLS23-reshare-party-v1-"))
	if oldKey != nil {
		h.Write(oldKey.ECDSAPub.X().Bytes())
		h.Write(oldKey.ECDSAPub.Y().Bytes())
	}
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
	buf[0] = byte(newThreshold)
	h.Write(buf[:])
	return h.Sum(nil)
}
