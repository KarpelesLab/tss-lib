package frostristretto255tss

import (
	"context"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Resharing reshares an existing FROST(ristretto255) key from an old
// committee to a new committee, preserving the GroupPublicKey. The protocol
// shape mirrors frosttss/resharing.go with the commitment scheme replaced by
// commitElements (a SHA-512 hash over 32-byte canonical Ristretto255
// encodings rather than the GG18-style FlattenECPoints + cmts).
type Resharing struct {
	ctx    context.Context
	params *tss.ReSharingParameters
	input  *Key

	// Old committee round-1 state.
	newVs        []group.Element
	newShares    []*vssShare
	vDecommit    []byte // commitElements decommit bytes (kept for round 3 broadcast)

	// New committee round-4 state.
	groupPubKey  group.Element
	round5NewKey *Key

	Done chan *Key
	Err  chan error
}

// NewResharing starts a FROST(ristretto255) resharing protocol.
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

func (rs *Resharing) round1Old() error {
	Pi := rs.params.PartyID()
	i := Pi.Index
	g := group.Ristretto255()

	subset, err := rs.input.SubsetForParties(rs.params.OldParties().IDs())
	if err != nil {
		return fmt.Errorf("SubsetForParties: %w", err)
	}
	rs.input = subset

	xi := rs.input.Xi
	ks := rs.input.Ks
	if rs.params.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d not satisfied by key count %d", rs.params.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(g, i, len(rs.params.OldParties().IDs()), xi, ks)

	newKs := rs.params.NewParties().IDs().Keys()
	vi, shares, err := vssCreate(g, rs.params.NewThreshold(), wi, newKs, rs.params.Rand())
	if err != nil {
		return fmt.Errorf("vssCreate: %w", err)
	}

	commit, decommit, err := commitElements(rs.params.Rand(), vi)
	if err != nil {
		return fmt.Errorf("commitElements: %w", err)
	}

	rs.newVs = vi
	rs.newShares = shares
	rs.vDecommit = decommit

	r1 := &resharingRound1msg{
		GroupPublicKey: rs.input.GroupPublicKey.Bytes(),
		VCommitment:    commit,
	}

	newParties := rs.params.NewParties().IDs()
	for _, Pj := range newParties {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("frost:ristretto255:reshare:round1", r1, Pi, Pj)
		rs.params.Broker().Receive(m)
	}
	if rs.params.IsNewCommittee() {
		selfMsg := tss.JsonWrap("frost:ristretto255:reshare:round1", r1, Pi, Pi)
		rs.params.Broker().Receive(selfMsg)
	}

	var newOtherIds []*tss.PartyID
	for _, Pj := range newParties {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		newOtherIds = append(newOtherIds, Pj)
	}
	if len(newOtherIds) == 0 {
		go rs.round3Old()
	} else {
		rcv := tss.NewJsonExpect[resharingRound2msg]("frost:ristretto255:reshare:round2", newOtherIds, func(_ []*tss.PartyID, _ []*resharingRound2msg) {
			rs.round3Old()
		})
		rs.params.Broker().Connect("frost:ristretto255:reshare:round2", rcv)
	}
	return nil
}

func (rs *Resharing) setupNewRound1Receiver() {
	allOldIds := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds, rs.params.OldParties().IDs())
	rcv := tss.NewJsonExpect[resharingRound1msg]("frost:ristretto255:reshare:round1", allOldIds, func(ids []*tss.PartyID, msgs []*resharingRound1msg) {
		rs.round2New(ids, msgs)
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round1", rcv)
}

func (rs *Resharing) round2New(oldIds []*tss.PartyID, r1msgs []*resharingRound1msg) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	Pi := rs.params.PartyID()
	g := group.Ristretto255()

	var pub group.Element
	for n, msg := range r1msgs {
		candidate, err := g.DecodeElement(msg.GroupPublicKey)
		if err != nil {
			rs.Err <- fmt.Errorf("party %s sent invalid GroupPublicKey: %w", oldIds[n], err)
			return
		}
		if pub == nil {
			pub = candidate
		} else if !pub.Equal(candidate) {
			rs.Err <- fmt.Errorf("party %s sent inconsistent GroupPublicKey", oldIds[n])
			return
		}
	}
	rs.groupPubKey = pub

	r2 := &resharingRound2msg{}
	for _, Pj := range rs.params.OldParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("frost:ristretto255:reshare:round2", r2, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	rs.setupNewRound3Receiver(oldIds, r1msgs)
}

func (rs *Resharing) setupNewRound3Receiver(oldIds []*tss.PartyID, r1msgs []*resharingRound1msg) {
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

	allOldIds := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds, rs.params.OldParties().IDs())

	rcv1 := tss.NewJsonExpect[resharingRound3msg1]("frost:ristretto255:reshare:round3-1", allOldIds, func(ids []*tss.PartyID, msgs []*resharingRound3msg1) {
		r3msg1s = msgs
		r3msg1Ids = ids
		check()
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round3-1", rcv1)

	allOldIds2 := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds2, rs.params.OldParties().IDs())

	rcv2 := tss.NewJsonExpect[resharingRound3msg2]("frost:ristretto255:reshare:round3-2", allOldIds2, func(ids []*tss.PartyID, msgs []*resharingRound3msg2) {
		r3msg2s = msgs
		r3msg2Ids = ids
		check()
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round3-2", rcv2)
}

func (rs *Resharing) round3Old() {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	Pi := rs.params.PartyID()
	g := group.Ristretto255()

	newParties := rs.params.NewParties().IDs()
	for j, Pj := range newParties {
		share := rs.newShares[j]
		r3m1 := &resharingRound3msg1{Share: g.EncodeScalar(share.Share)}
		m := tss.JsonWrap("frost:ristretto255:reshare:round3-1", r3m1, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// vDecommit splits into 32-byte chunks: randomness (1 chunk) + threshold+1 element chunks
	chunks := make([][]byte, 0, (len(rs.vDecommit)/32))
	for k := 0; k < len(rs.vDecommit); k += 32 {
		chunks = append(chunks, rs.vDecommit[k:k+32])
	}
	r3m2 := &resharingRound3msg2{VDecommitment: chunks}
	for _, Pj := range newParties {
		m := tss.JsonWrap("frost:ristretto255:reshare:round3-2", r3m2, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	rs.setupOldRound4Receiver()
}

func (rs *Resharing) setupOldRound4Receiver() {
	Pi := rs.params.PartyID()
	var otherNewIds []*tss.PartyID
	for _, Pj := range rs.params.NewParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		otherNewIds = append(otherNewIds, Pj)
	}
	if len(otherNewIds) == 0 {
		go rs.round5Old()
		return
	}
	rcv := tss.NewJsonExpect[resharingRound4msg]("frost:ristretto255:reshare:round4", otherNewIds, func(_ []*tss.PartyID, _ []*resharingRound4msg) {
		rs.round5Old()
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round4", rcv)
}

func (rs *Resharing) round4New(
	oldIds []*tss.PartyID,
	r1msgs []*resharingRound1msg,
	r3msg1Ids []*tss.PartyID,
	r3msg1s []*resharingRound3msg1,
	r3msg2Ids []*tss.PartyID,
	r3msg2s []*resharingRound3msg2,
) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	Pi := rs.params.PartyID()
	g := group.Ristretto255()
	allOldIds := rs.params.OldParties().IDs()

	oldKeyToIdx := make(map[string]int)
	for idx, p := range allOldIds {
		oldKeyToIdx[p.KeyInt().String()] = idx
	}
	r1ByOldIdx := make(map[int]*resharingRound1msg)
	for n, pid := range oldIds {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r1ByOldIdx[idx] = r1msgs[n]
		}
	}
	r3m1ByOldIdx := make(map[int]*resharingRound3msg1)
	for n, pid := range r3msg1Ids {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r3m1ByOldIdx[idx] = r3msg1s[n]
		}
	}
	r3m2ByOldIdx := make(map[int]*resharingRound3msg2)
	for n, pid := range r3msg2Ids {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r3m2ByOldIdx[idx] = r3msg2s[n]
		}
	}

	newXi := big.NewInt(0)
	modQ := common.ModInt(g.Order())
	vjc := make([][]group.Element, len(allOldIds))

	for j := 0; j < len(allOldIds); j++ {
		r1msg, ok := r1ByOldIdx[j]
		if !ok {
			rs.Err <- fmt.Errorf("missing round1 message from old party %d", j)
			return
		}
		r3msg1, ok := r3m1ByOldIdx[j]
		if !ok {
			rs.Err <- fmt.Errorf("missing round3-1 message from old party %d", j)
			return
		}
		r3msg2, ok := r3m2ByOldIdx[j]
		if !ok {
			rs.Err <- fmt.Errorf("missing round3-2 message from old party %d", j)
			return
		}

		// Reassemble decommit bytes and verify against the commit.
		decommit := make([]byte, 0, 32*(rs.params.NewThreshold()+2))
		for _, chunk := range r3msg2.VDecommitment {
			decommit = append(decommit, chunk...)
		}
		ok2, vj, err := verifyCommitElements(g, r1msg.VCommitment, decommit, rs.params.NewThreshold()+1)
		if err != nil {
			rs.Err <- fmt.Errorf("decommit decode for old party %d: %w", j, err)
			return
		}
		if !ok2 {
			rs.Err <- fmt.Errorf("commit verify failed for old party %d", j)
			return
		}
		vjc[j] = vj

		shareInt, err := g.DecodeScalar(r3msg1.Share)
		if err != nil {
			rs.Err <- fmt.Errorf("invalid share scalar from old party %d: %w", j, err)
			return
		}
		sharej := &vssShare{
			Threshold: rs.params.NewThreshold(),
			ID:        Pi.KeyInt(),
			Share:     shareInt,
		}
		if !sharej.verify(g, rs.params.NewThreshold(), vj) {
			rs.Err <- fmt.Errorf("VSS share verification failed for old party %d", j)
			return
		}
		newXi = new(big.Int).Add(newXi, sharej.Share)
	}

	// Aggregate Vc and verify Vc[0] == groupPubKey.
	Vc := make([]group.Element, rs.params.NewThreshold()+1)
	for c := 0; c <= rs.params.NewThreshold(); c++ {
		Vc[c] = vjc[0][c].Clone()
		for j := 1; j < len(vjc); j++ {
			sum, err := Vc[c].Add(vjc[j][c])
			if err != nil {
				rs.Err <- fmt.Errorf("Vc[%d] aggregate: %w", c, err)
				return
			}
			Vc[c] = sum
		}
	}
	if !Vc[0].Equal(rs.groupPubKey) {
		rs.Err <- fmt.Errorf("assertion failed: V_0 != GroupPublicKey")
		return
	}

	newKs := make([]*big.Int, 0, rs.params.NewPartyCount())
	newBigXjs := make([]group.Element, rs.params.NewPartyCount())
	for j := 0; j < rs.params.NewPartyCount(); j++ {
		Pj := rs.params.NewParties().IDs()[j]
		kj := Pj.KeyInt()
		newKs = append(newKs, kj)
		newBigXj := Vc[0].Clone()
		z := big.NewInt(1)
		for c := 1; c <= rs.params.NewThreshold(); c++ {
			z = modQ.Mul(z, kj)
			next, err := newBigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				rs.Err <- fmt.Errorf("computing newBigXj: %w", err)
				return
			}
			newBigXj = next
		}
		newBigXjs[j] = newBigXj
	}

	newXi = new(big.Int).Mod(newXi, g.Order())
	newKey := NewKey(rs.params.NewPartyCount())
	newKey.Xi = newXi
	newKey.ShareID = Pi.KeyInt()
	newKey.Ks = newKs
	newKey.BigXj = newBigXjs
	newKey.GroupPublicKey = rs.groupPubKey
	rs.round5NewKey = newKey

	r4 := &resharingRound4msg{}
	for _, Pj := range rs.params.OldAndNewParties() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("frost:ristretto255:reshare:round4", r4, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	if rs.params.IsOldCommittee() {
		return
	}

	var otherNewIds []*tss.PartyID
	for _, Pj := range rs.params.NewParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		otherNewIds = append(otherNewIds, Pj)
	}
	if len(otherNewIds) == 0 {
		rs.Done <- newKey
		return
	}
	rcv := tss.NewJsonExpect[resharingRound4msg]("frost:ristretto255:reshare:round4", otherNewIds, func(_ []*tss.PartyID, _ []*resharingRound4msg) {
		rs.Done <- newKey
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round4", rcv)
}

func (rs *Resharing) round5Old() {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	if rs.input != nil {
		rs.input.Xi.SetInt64(0)
	}
	if rs.params.IsNewCommittee() && rs.round5NewKey != nil {
		rs.Done <- rs.round5NewKey
	} else {
		rs.Done <- nil
	}
}
