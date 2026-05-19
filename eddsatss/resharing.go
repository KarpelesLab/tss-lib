package eddsatss

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	cmts "github.com/KarpelesLab/tss-lib/v2/crypto/commitments"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Resharing tracks a key resharing operation between old and new committees.
type Resharing struct {
	ctx    context.Context
	params *tss.ReSharingParameters
	input  *Key // old committee's key data (nil for pure new members)

	// Round 1 temp (old committee)
	newVs     vss.Vs
	newShares vss.Shares
	vD        cmts.HashDeCommitment

	// Round 4 temp (new committee)
	eddsaPub     *crypto.ECPoint // received from old committee
	round5NewKey *Key            // new key computed in round4, saved in round5

	Done chan *Key
	Err  chan error

	// Once-guards on Done/Err so multi-writer error paths cannot block on
	// the size-1 buffer. See once_send.go for the rationale.
	doneOnce sync.Once
	errOnce  sync.Once
}

// NewResharing creates a new Resharing instance and starts the protocol.
// For old committee members, input must be their existing key data.
// For pure new members, input should be nil.
func NewResharing(ctx context.Context, params *tss.ReSharingParameters, input *Key) (*Resharing, error) {
	rs := &Resharing{
		ctx:    ctx,
		params: params,
		input:  input,
		Done:   make(chan *Key, 1),
		Err:    make(chan error, 1),
	}

	if params.IsOldCommittee() {
		if err := rs.round1Old(); err != nil {
			return nil, err
		}
	}

	if params.IsNewCommittee() {
		rs.setupNewRound1Receiver()
	}

	return rs, nil
}

// round1Old: old committee computes wi, creates VSS shares for new committee, broadcasts commitment.
func (rs *Resharing) round1Old() error {
	Pi := rs.params.PartyID()
	i := Pi.Index
	ec := rs.params.EC()

	// The input key's Ks/BigXj are indexed by the original keygen party order, but the old
	// committee may be a strict subset of those parties. Reindex against OldParties so every
	// subsequent rs.input.* access is old-committee-indexed.
	subset, err := rs.input.SubsetForParties(rs.params.OldParties().IDs())
	if err != nil {
		return fmt.Errorf("SubsetForParties: %w", err)
	}
	rs.input = subset

	// 1. PrepareForSigning() -> wi
	xi := rs.input.Xi
	ks := rs.input.Ks
	if rs.params.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", rs.params.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(ec, i, len(rs.params.OldParties().IDs()), xi, ks)

	// 2. VSS-share wi for new committee using new threshold and new party keys
	newKs := rs.params.NewParties().IDs().Keys()
	vi, shares, err := vss.Create(ec, rs.params.NewThreshold(), wi, newKs, rs.params.Rand())
	if err != nil {
		return fmt.Errorf("vss.Create: %w", err)
	}

	// 3. Commit to VSS polynomial
	flatVis, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return fmt.Errorf("FlattenECPoints: %w", err)
	}
	vCmt := cmts.NewHashCommitment(rs.params.Rand(), flatVis...)

	// 4. Save temp data
	rs.newVs = vi
	rs.newShares = shares
	rs.vD = vCmt.D

	// 5. Broadcast commitment + EDDSAPub to all new parties (excluding self if in both)
	r1msg := &resharingRound1msg{
		EDDSAPubX:   rs.input.EDDSAPub.X().Bytes(),
		EDDSAPubY:   rs.input.EDDSAPub.Y().Bytes(),
		VCommitment: vCmt.C.Bytes(),
	}

	newParties := rs.params.NewParties().IDs()
	for _, Pj := range newParties {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue // skip self
		}
		m := tss.JsonWrap("eddsa:reshare:round1", r1msg, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// If this party is also in the new committee, deliver round1 msg to self
	if rs.params.IsNewCommittee() {
		selfMsg := tss.JsonWrap("eddsa:reshare:round1", r1msg, Pi, Pi)
		rs.params.Broker().Receive(selfMsg)
	}

	// Register receiver for round 2 ACKs from new committee
	// For dual parties, we count self-ACK as immediate (we know we'll ACK ourselves).
	var newOtherIds []*tss.PartyID
	for _, Pj := range newParties {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		newOtherIds = append(newOtherIds, Pj)
	}

	if len(newOtherIds) == 0 {
		// Self is the only new party; proceed directly to round3
		// (This happens if old and new committees are identical single-party)
		go rs.round3Old()
	} else {
		rcv := tss.NewJsonExpect[resharingRound2msg]("eddsa:reshare:round2", newOtherIds, func(ids []*tss.PartyID, msgs []*resharingRound2msg) {
			rs.round3Old()
		})
		rs.params.Broker().Connect("eddsa:reshare:round2", rcv)
	}

	return nil
}

// setupNewRound1Receiver registers a receiver for round 1 messages from old committee.
func (rs *Resharing) setupNewRound1Receiver() {
	// Expect round1 messages from ALL old committee members.
	// For dual parties, the self-message was already sent in round1Old via Broker.Receive
	// with From=self, which will be routed back to us.
	allOldIds := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds, rs.params.OldParties().IDs())

	rcv := tss.NewJsonExpect[resharingRound1msg]("eddsa:reshare:round1", allOldIds, func(ids []*tss.PartyID, msgs []*resharingRound1msg) {
		rs.round2New(ids, msgs)
	})
	rs.params.Broker().Connect("eddsa:reshare:round1", rcv)
}

// round2New: new committee receives round1 messages, verifies EDDSAPub consistency, sends ACK.
func (rs *Resharing) round2New(oldIds []*tss.PartyID, r1msgs []*resharingRound1msg) {
	if rs.ctx.Err() != nil {
		sendOnce(&rs.errOnce, rs.Err, rs.ctx.Err())
		return
	}
	Pi := rs.params.PartyID()
	ec := rs.params.EC()

	// Verify all old parties sent the same EDDSAPub
	var eddsaPub *crypto.ECPoint
	for n, msg := range r1msgs {
		pubX := new(big.Int).SetBytes(msg.EDDSAPubX)
		pubY := new(big.Int).SetBytes(msg.EDDSAPubY)
		candidate, err := crypto.NewECPoint(ec, pubX, pubY)
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("party %s sent invalid EDDSAPub: %w", oldIds[n], err))
			return
		}
		if eddsaPub == nil {
			eddsaPub = candidate
		} else if !eddsaPub.Equals(candidate) {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("party %s sent different EDDSAPub", oldIds[n]))
			return
		}
	}
	rs.eddsaPub = eddsaPub

	// Send ACK to all old committee parties (excluding self if in both)
	r2msg := &resharingRound2msg{}
	for _, Pj := range rs.params.OldParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("eddsa:reshare:round2", r2msg, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Register receivers for round 3 messages from old committee
	rs.setupNewRound3Receiver(oldIds, r1msgs)
}

// setupNewRound3Receiver registers receivers for round 3 P2P shares and broadcast decommitments.
func (rs *Resharing) setupNewRound3Receiver(oldIds []*tss.PartyID, r1msgs []*resharingRound1msg) {
	// We need both round3-1 (P2P shares) and round3-2 (broadcast decommitments) from all old parties.
	var counter int32
	var r3msg1s []*resharingRound3msg1
	var r3msg1Ids []*tss.PartyID
	var r3msg2s []*resharingRound3msg2
	var r3msg2Ids []*tss.PartyID

	check := func() {
		if atomic.AddInt32(&counter, 1) == 2 {
			rs.round4New(oldIds, r1msgs, r3msg1Ids, r3msg1s, r3msg2Ids, r3msg2s)
		}
	}

	// For round3-1 (P2P), each old party sends us a share directly.
	allOldIds := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds, rs.params.OldParties().IDs())

	rcv1 := tss.NewJsonExpect[resharingRound3msg1]("eddsa:reshare:round3-1", allOldIds, func(ids []*tss.PartyID, msgs []*resharingRound3msg1) {
		r3msg1s = msgs
		r3msg1Ids = ids
		check()
	})
	rs.params.Broker().Connect("eddsa:reshare:round3-1", rcv1)

	// For round3-2 (broadcast decommitment), all old parties broadcast.
	allOldIds2 := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds2, rs.params.OldParties().IDs())

	rcv2 := tss.NewJsonExpect[resharingRound3msg2]("eddsa:reshare:round3-2", allOldIds2, func(ids []*tss.PartyID, msgs []*resharingRound3msg2) {
		r3msg2s = msgs
		r3msg2Ids = ids
		check()
	})
	rs.params.Broker().Connect("eddsa:reshare:round3-2", rcv2)
}

// round3Old: old committee sends P2P VSS shares to each new party and broadcasts decommitment.
func (rs *Resharing) round3Old() {
	if rs.ctx.Err() != nil {
		sendOnce(&rs.errOnce, rs.Err, rs.ctx.Err())
		return
	}
	Pi := rs.params.PartyID()

	// Send P2P share to each new party
	newParties := rs.params.NewParties().IDs()
	for j, Pj := range newParties {
		share := rs.newShares[j]
		r3msg1 := &resharingRound3msg1{
			Share: share.Share.Bytes(),
		}
		m := tss.JsonWrap("eddsa:reshare:round3-1", r3msg1, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Broadcast decommitment to all new parties
	vDBytes := common.BigIntsToBytes(rs.vD)
	r3msg2 := &resharingRound3msg2{
		VDecommitment: vDBytes,
	}
	for _, Pj := range newParties {
		m := tss.JsonWrap("eddsa:reshare:round3-2", r3msg2, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Register receiver for round 4 ACKs from new committee
	rs.setupOldRound4Receiver()
}

// setupOldRound4Receiver registers for round 4 ACKs (old committee waiting for new committee).
func (rs *Resharing) setupOldRound4Receiver() {
	Pi := rs.params.PartyID()

	// Expect ACKs from all new parties except self (if dual).
	// For dual parties, when we reach round4New (new side), we know we're done on that side,
	// so we don't need to ACK ourselves.
	var otherNewIds []*tss.PartyID
	for _, Pj := range rs.params.NewParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		otherNewIds = append(otherNewIds, Pj)
	}

	if len(otherNewIds) == 0 {
		// Only new party is self; proceed directly
		go rs.round5Old()
		return
	}

	rcv := tss.NewJsonExpect[resharingRound4msg]("eddsa:reshare:round4", otherNewIds, func(ids []*tss.PartyID, msgs []*resharingRound4msg) {
		rs.round5Old()
	})
	rs.params.Broker().Connect("eddsa:reshare:round4", rcv)
}

// round4New: new committee verifies decommitments, VSS shares, computes new key data.
func (rs *Resharing) round4New(
	oldIds []*tss.PartyID,
	r1msgs []*resharingRound1msg,
	r3msg1Ids []*tss.PartyID,
	r3msg1s []*resharingRound3msg1,
	r3msg2Ids []*tss.PartyID,
	r3msg2s []*resharingRound3msg2,
) {
	if rs.ctx.Err() != nil {
		sendOnce(&rs.errOnce, rs.Err, rs.ctx.Err())
		return
	}
	Pi := rs.params.PartyID()
	ec := rs.params.EC()
	allOldIds := rs.params.OldParties().IDs()

	// Build lookup maps: old party KeyInt -> index in allOldIds
	oldKeyToIdx := make(map[string]int)
	for idx, p := range allOldIds {
		oldKeyToIdx[p.KeyInt().String()] = idx
	}

	// Build lookup: old party index -> r1msg
	r1ByOldIdx := make(map[int]*resharingRound1msg)
	for n, pid := range oldIds {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r1ByOldIdx[idx] = r1msgs[n]
		}
	}

	// Build lookup: old party index -> r3msg1 (shares)
	r3m1ByOldIdx := make(map[int]*resharingRound3msg1)
	for n, pid := range r3msg1Ids {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r3m1ByOldIdx[idx] = r3msg1s[n]
		}
	}

	// Build lookup: old party index -> r3msg2 (decommitments)
	r3m2ByOldIdx := make(map[int]*resharingRound3msg2)
	for n, pid := range r3msg2Ids {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r3m2ByOldIdx[idx] = r3msg2s[n]
		}
	}

	newXi := big.NewInt(0)
	modQ := common.ModInt(ec.Params().N)

	vjc := make([][]*crypto.ECPoint, len(allOldIds))

	for j := 0; j < len(allOldIds); j++ {
		r1msg, ok := r1ByOldIdx[j]
		if !ok {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("missing round1 message from old party %d", j))
			return
		}
		r3msg1, ok := r3m1ByOldIdx[j]
		if !ok {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("missing round3-1 message from old party %d", j))
			return
		}
		r3msg2, ok := r3m2ByOldIdx[j]
		if !ok {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("missing round3-2 message from old party %d", j))
			return
		}

		// Verify decommitment
		vCj := new(big.Int).SetBytes(r1msg.VCommitment)
		vDj := cmts.NewHashDeCommitmentFromBytes(r3msg2.VDecommitment)
		cmtDeCmt := cmts.HashCommitDecommit{C: vCj, D: vDj}
		ok2, flatVs := cmtDeCmt.DeCommit()
		if !ok2 || len(flatVs) != (rs.params.NewThreshold()+1)*2 {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("de-commitment verify failed for old party %d", j))
			return
		}

		vj, err := crypto.UnFlattenECPoints(ec, flatVs)
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("UnFlattenECPoints for old party %d: %w", j, err))
			return
		}

		// Apply EightInvEight
		for idx, v := range vj {
			vj[idx] = v.EightInvEight()
		}

		vjc[j] = vj

		// Verify VSS share
		sharej := &vss.Share{
			Threshold: rs.params.NewThreshold(),
			ID:        Pi.KeyInt(),
			Share:     new(big.Int).SetBytes(r3msg1.Share),
		}
		if !sharej.Verify(ec, rs.params.NewThreshold(), vj) {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("VSS share verification failed for old party %d", j))
			return
		}

		newXi = new(big.Int).Add(newXi, sharej.Share)
	}

	// Compute Vc: aggregate polynomial commitments
	var err error
	Vc := make([]*crypto.ECPoint, rs.params.NewThreshold()+1)
	for c := 0; c <= rs.params.NewThreshold(); c++ {
		Vc[c] = vjc[0][c]
		for j := 1; j < len(vjc); j++ {
			Vc[c], err = Vc[c].Add(vjc[j][c])
			if err != nil {
				sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("Vc[%d].Add(vjc[%d][%d]): %w", c, j, c, err))
				return
			}
		}
	}

	// Verify Vc[0] == EDDSAPub
	if !Vc[0].Equals(rs.eddsaPub) {
		sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("assertion failed: V_0 != EDDSAPub"))
		return
	}

	// Compute newBigXj for each new party
	newKs := make([]*big.Int, 0, rs.params.NewPartyCount())
	newBigXjs := make([]*crypto.ECPoint, rs.params.NewPartyCount())
	for j := 0; j < rs.params.NewPartyCount(); j++ {
		Pj := rs.params.NewParties().IDs()[j]
		kj := Pj.KeyInt()
		newKs = append(newKs, kj)
		newBigXj := Vc[0]
		z := new(big.Int).SetInt64(1)
		for c := 1; c <= rs.params.NewThreshold(); c++ {
			z = modQ.Mul(z, kj)
			newBigXj, err = newBigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("computing newBigXj: %w", err))
				return
			}
		}
		newBigXjs[j] = newBigXj
	}

	newXi = new(big.Int).Mod(newXi, ec.Params().N)

	// Build new key
	newKey := NewKey(rs.params.NewPartyCount())
	newKey.Xi = newXi
	newKey.ShareID = Pi.KeyInt()
	newKey.Ks = newKs
	newKey.BigXj = newBigXjs
	newKey.EDDSAPub = rs.eddsaPub

	// Store for round5
	rs.round5NewKey = newKey

	// Send ACK to all old+new parties (excluding self)
	r4msg := &resharingRound4msg{}
	for _, Pj := range rs.params.OldAndNewParties() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("eddsa:reshare:round4", r4msg, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	if rs.params.IsOldCommittee() {
		// Dual party: old side already registered for round4 ACKs.
		// round5Old will be called by that handler and will deliver newKey.
		return
	}

	// Pure new party: register for round 4 ACKs from other new parties
	var otherNewIds []*tss.PartyID
	for _, Pj := range rs.params.NewParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		otherNewIds = append(otherNewIds, Pj)
	}

	if len(otherNewIds) == 0 {
		// Only new party is self; save directly
		sendOnce(&rs.doneOnce, rs.Done, newKey)
		return
	}

	rcv := tss.NewJsonExpect[resharingRound4msg]("eddsa:reshare:round4", otherNewIds, func(ids []*tss.PartyID, msgs []*resharingRound4msg) {
		sendOnce(&rs.doneOnce, rs.Done, newKey)
	})
	rs.params.Broker().Connect("eddsa:reshare:round4", rcv)
}

// round5Old: old committee zeros Xi and signals done.
func (rs *Resharing) round5Old() {
	if rs.ctx.Err() != nil {
		sendOnce(&rs.errOnce, rs.Err, rs.ctx.Err())
		return
	}
	if rs.input != nil {
		rs.input.Xi.SetInt64(0)
	}

	if rs.params.IsNewCommittee() && rs.round5NewKey != nil {
		// Dual party: deliver the new key
		sendOnce(&rs.doneOnce, rs.Done, rs.round5NewKey)
	} else {
		// Pure old party: done with nil key (Xi zeroed)
		sendOnce(&rs.doneOnce, rs.Done, nil)
	}
}
