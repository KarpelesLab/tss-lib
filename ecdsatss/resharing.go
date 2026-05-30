package ecdsatss

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	cmts "github.com/KarpelesLab/tss-lib/v2/crypto/commitments"
	"github.com/KarpelesLab/tss-lib/v2/crypto/dlnproof"
	"github.com/KarpelesLab/tss-lib/v2/crypto/facproof"
	"github.com/KarpelesLab/tss-lib/v2/crypto/modproof"
	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Resharing tracks an ECDSA key resharing operation from an old committee to a new committee.
type Resharing struct {
	ctx    context.Context
	params *tss.ReSharingParameters
	input  *Key // old committee key data (nil for pure new members)

	// temp storage for old committee
	vd        cmts.HashDeCommitment
	newShares vss.Shares

	// temp storage for new committee
	newXi     *big.Int
	newKs     []*big.Int
	newBigXjs []*crypto.ECPoint

	// Paillier/proof data for new committee
	preParams *LocalPreParams
	newKey    *Key // key being built for new committee

	// SSID
	ssid      []byte
	ssidNonce *big.Int

	// round synchronization: new committee waits for 3 message types
	// (r2msg1 from new committee, r3msg1 P2P from old, r3msg2 broadcast from old)
	newR4pending int32

	// round synchronization for round 5 (new committee waits for FacProof P2P + ACK broadcast)
	newR5pending int32

	// saved round 1 messages from old committee (needed in round 4)
	r1msgsFrom []*tss.PartyID
	r1msgs     []*resharingRound1msg

	// round 2 msg1 from other new committee members
	r2msg1From []*tss.PartyID
	r2msg1     []*resharingRound2msg1

	// round 3 messages from old committee
	r3msg1From []*tss.PartyID
	r3msg1     []*resharingRound3msg1
	r3msg2From []*tss.PartyID
	r3msg2     []*resharingRound3msg2

	// round 4 messages from other new committee members
	r4msg1From []*tss.PartyID
	r4msg1     []*resharingRound4msg1
	r4msg2From []*tss.PartyID
	r4msg2     []*resharingRound4msg2

	Done chan *Key
	Err  chan error
}

// NewResharing creates a new Resharing instance and begins the resharing protocol.
// For old committee members, input is their existing key data.
// For new committee members, input is nil and optionalPreParams provides the Paillier pre-parameters.
func NewResharing(ctx context.Context, params *tss.ReSharingParameters, input *Key, optionalPreParams ...LocalPreParams) (*Resharing, error) {
	rs := &Resharing{
		ctx:    ctx,
		params: params,
		input:  input,
		Done:   make(chan *Key, 1),
		Err:    make(chan error, 1),
	}

	if params.IsNewCommittee() {
		rs.newKey = NewKey(params.NewPartyCount())
		if len(optionalPreParams) > 0 {
			rs.newKey.LocalPreParams = optionalPreParams[0]
		}
	}

	rs.ssidNonce = new(big.Int).SetUint64(0)

	if params.IsOldCommittee() {
		err := rs.round1Old()
		if err != nil {
			return nil, err
		}
	}
	if params.IsNewCommittee() {
		rs.round1New()
	}

	return rs, nil
}

// getSSID computes the session ID from the old committee's key data.
func (rs *Resharing) getSSID() ([]byte, error) {
	ec := rs.params.EC()
	ssidList := []*big.Int{ec.Params().P, ec.Params().N, ec.Params().B, ec.Params().Gx, ec.Params().Gy}
	ssidList = append(ssidList, rs.params.OldParties().IDs().Keys()...)
	BigXjList, err := crypto.FlattenECPoints(rs.input.BigXj)
	if err != nil {
		return nil, fmt.Errorf("read BigXj failed: %w", err)
	}
	ssidList = append(ssidList, BigXjList...)
	ssidList = append(ssidList, rs.input.NTildej...)
	ssidList = append(ssidList, rs.input.H1j...)
	ssidList = append(ssidList, rs.input.H2j...)
	ssidList = append(ssidList, big.NewInt(1)) // round number
	ssidList = append(ssidList, rs.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()
	return ssid, nil
}

// prepareForSigning computes the Lagrange coefficient wi for the old committee member.
func (rs *Resharing) prepareForSigning(subsetKey *Key) (*big.Int, error) {
	ec := rs.params.EC()
	i := rs.params.PartyID().Index
	xi := subsetKey.Xi
	ks := subsetKey.Ks
	bigXs := subsetKey.BigXj
	pax := len(ks)

	if rs.params.Threshold()+1 > pax {
		return nil, fmt.Errorf("t+1=%d is not satisfied by the key count of %d", rs.params.Threshold()+1, pax)
	}
	if len(ks) != len(bigXs) {
		return nil, fmt.Errorf("len(ks) != len(bigXs) (%d != %d)", len(ks), len(bigXs))
	}
	if pax <= i {
		return nil, fmt.Errorf("pax <= i (%d <= %d)", pax, i)
	}

	modQ := common.ModInt(ec.Params().N)
	wi := new(big.Int).Set(xi)
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			return nil, fmt.Errorf("index of two parties are equal")
		}
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}
	return wi, nil
}

// ---- Round 1 (Old committee) ---- //

func (rs *Resharing) round1Old() error {
	Pi := rs.params.PartyID()

	// Reindex rs.input against the old committee so every per-party slice lookup below
	// uses old-committee indices rather than keygen-party indices.
	subsetKey, err := rs.input.SubsetForParties(rs.params.OldParties().IDs())
	if err != nil {
		return fmt.Errorf("SubsetForParties: %w", err)
	}
	rs.input = subsetKey

	// Compute SSID
	ssid, err := rs.getSSID()
	if err != nil {
		return fmt.Errorf("failed to compute SSID: %w", err)
	}
	rs.ssid = ssid

	// PrepareForSigning() -> w_i
	wi, err := rs.prepareForSigning(subsetKey)
	if err != nil {
		return fmt.Errorf("PrepareForSigning failed: %w", err)
	}

	// Create VSS shares for new committee
	newKs := rs.params.NewParties().IDs().Keys()
	vi, shares, err := vss.Create(rs.params.EC(), rs.params.NewThreshold(), wi, newKs, rs.params.Rand())
	if err != nil {
		return fmt.Errorf("VSS Create failed: %w", err)
	}

	// Create commitment
	flatVis, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return fmt.Errorf("FlattenECPoints failed: %w", err)
	}
	vCmt := cmts.NewHashCommitment(rs.params.Rand(), flatVis...)

	// Store temp data
	rs.vd = vCmt.D
	rs.newShares = shares

	// Broadcast R1 message to new committee
	r1msg := &resharingRound1msg{
		ECDSAPubX:   rs.input.ECDSAPub.X().Bytes(),
		ECDSAPubY:   rs.input.ECDSAPub.Y().Bytes(),
		VCommitment: vCmt.C.Bytes(),
		SSID:        ssid,
	}

	newIDs := rs.params.NewParties().IDs()
	for _, Pj := range newIDs {
		m := tss.JsonWrap("ecdsa:resharing:round1", r1msg, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Old committee now waits for ACK from new committee (round 2 msg2)
	r2rcv := tss.NewJsonExpect[resharingRound2msg2]("ecdsa:resharing:round2-2", newIDs, rs.onR2msg2Old)
	rs.params.Broker().Connect("ecdsa:resharing:round2-2", r2rcv)

	return nil
}

// ---- Round 1 (New committee setup) ---- //

func (rs *Resharing) round1New() {
	oldIDs := rs.params.OldParties().IDs()
	r1rcv := tss.NewJsonExpect[resharingRound1msg]("ecdsa:resharing:round1", oldIDs, rs.onR1New)
	rs.params.Broker().Connect("ecdsa:resharing:round1", r1rcv)
}

// ---- Round 2 (New committee receives R1, sends Paillier+proofs to new, ACK to old) ---- //

func (rs *Resharing) onR1New(from []*tss.PartyID, msgs []*resharingRound1msg) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	Pi := rs.params.PartyID()
	i := Pi.Index
	ec := rs.params.EC()
	_ = ec

	// Save R1 messages for later use in round 4
	rs.r1msgsFrom = from
	rs.r1msgs = msgs

	// Check consistency of SSID across all old committee members
	var SSID []byte
	for j, msg := range msgs {
		if SSID == nil {
			SSID = msg.SSID
		} else if !bytes.Equal(SSID, msg.SSID) {
			rs.Err <- fmt.Errorf("SSID mismatch from old party %s", from[j])
			return
		}
	}
	rs.ssid = SSID

	// Verify and save ECDSAPub from old committee
	var ecdsaPub *crypto.ECPoint
	for j, msg := range msgs {
		candidate, err := crypto.NewECPoint(ec, new(big.Int).SetBytes(msg.ECDSAPubX), new(big.Int).SetBytes(msg.ECDSAPubY))
		if err != nil {
			rs.Err <- fmt.Errorf("unable to unmarshal ECDSA pub from party %s: %w", from[j], err)
			return
		}
		if ecdsaPub == nil {
			ecdsaPub = candidate
		} else if !ecdsaPub.Equals(candidate) {
			rs.Err <- fmt.Errorf("ECDSA pub key mismatch from party %s", from[j])
			return
		}
	}
	rs.newKey.ECDSAPub = ecdsaPub

	// Generate or validate Paillier pre-params
	var preParams *LocalPreParams
	if rs.newKey.LocalPreParams.Validate() && !rs.newKey.LocalPreParams.ValidateWithProof() {
		rs.Err <- errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib")
		return
	} else if rs.newKey.LocalPreParams.ValidateWithProof() {
		preParams = &rs.newKey.LocalPreParams
	} else {
		ctx, cancel := context.WithTimeout(rs.ctx, rs.params.SafePrimeGenTimeout())
		defer cancel()
		var err error
		preParams, err = (&LocalPreGenerator{Context: ctx, Rand: rs.params.Rand(), Concurrency: rs.params.Concurrency()}).Generate()
		if err != nil {
			rs.Err <- fmt.Errorf("pre-params generation failed: %w", err)
			return
		}
	}
	rs.preParams = preParams
	rs.newKey.LocalPreParams = *preParams
	rs.newKey.PaillierSK = preParams.PaillierSK
	rs.newKey.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	rs.newKey.NTildej[i] = preParams.NTildei
	rs.newKey.H1j[i] = preParams.H1i
	rs.newKey.H2j[i] = preParams.H2i

	// Generate DLN proofs
	dlnProof1 := dlnproof.NewDLNProof(preParams.H1i, preParams.H2i, preParams.Alpha, preParams.P, preParams.Q, preParams.NTildei, rs.params.Rand())
	dlnProof2 := dlnproof.NewDLNProof(preParams.H2i, preParams.H1i, preParams.Beta, preParams.P, preParams.Q, preParams.NTildei, rs.params.Rand())

	// Generate ModProof
	modProofObj := &modproof.ProofMod{W: zero, X: *new([80]*big.Int), A: zero, B: zero, Z: *new([80]*big.Int)}
	ContextI := append(rs.ssid, big.NewInt(int64(i)).Bytes()...)
	if !rs.params.NoProofMod() {
		var err error
		modProofObj, err = modproof.NewProof(ContextI, preParams.PaillierSK.N, preParams.PaillierSK.P, preParams.PaillierSK.Q, rs.params.Rand())
		if err != nil {
			rs.Err <- fmt.Errorf("ModProof generation failed: %w", err)
			return
		}
	}

	modPfBzs := modProofObj.Bytes()
	dlnProof1Bz, err := dlnProof1.Serialize()
	if err != nil {
		rs.Err <- fmt.Errorf("DLN proof 1 serialize failed: %w", err)
		return
	}
	dlnProof2Bz, err := dlnProof2.Serialize()
	if err != nil {
		rs.Err <- fmt.Errorf("DLN proof 2 serialize failed: %w", err)
		return
	}

	// Broadcast R2 msg1 (Paillier+proofs) to other new committee members
	r2msg1 := &resharingRound2msg1{
		PaillierN:  preParams.PaillierSK.PublicKey.N.Bytes(),
		ModProof:   modPfBzs[:],
		NTilde:     preParams.NTildei.Bytes(),
		H1:         preParams.H1i.Bytes(),
		H2:         preParams.H2i.Bytes(),
		Dlnproof_1: dlnProof1Bz,
		Dlnproof_2: dlnProof2Bz,
	}

	newIDs := rs.params.NewParties().IDs()
	for _, Pj := range newIDs {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("ecdsa:resharing:round2-1", r2msg1, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Broadcast R2 msg2 (ACK) to old committee
	r2msg2 := &resharingRound2msg2{}
	oldIDs := rs.params.OldParties().IDs()
	for _, Pj := range oldIDs {
		m := tss.JsonWrap("ecdsa:resharing:round2-2", r2msg2, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// New committee now waits for 3 things:
	// 1. R2 msg1 from other new committee members
	// 2. R3 msg1 P2P from old committee
	// 3. R3 msg2 broadcast from old committee
	var otherNewIDs []*tss.PartyID
	for _, Pj := range newIDs {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		otherNewIDs = append(otherNewIDs, Pj)
	}

	atomic.StoreInt32(&rs.newR4pending, 3)

	r2m1rcv := tss.NewJsonExpect[resharingRound2msg1]("ecdsa:resharing:round2-1", otherNewIDs, rs.onR2msg1New)
	rs.params.Broker().Connect("ecdsa:resharing:round2-1", r2m1rcv)

	r3m1rcv := tss.NewJsonExpect[resharingRound3msg1]("ecdsa:resharing:round3-1", oldIDs, rs.onR3msg1New)
	rs.params.Broker().Connect("ecdsa:resharing:round3-1", r3m1rcv)

	r3m2rcv := tss.NewJsonExpect[resharingRound3msg2]("ecdsa:resharing:round3-2", oldIDs, rs.onR3msg2New)
	rs.params.Broker().Connect("ecdsa:resharing:round3-2", r3m2rcv)
}

func (rs *Resharing) onR2msg1New(from []*tss.PartyID, msgs []*resharingRound2msg1) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	rs.r2msg1From = from
	rs.r2msg1 = msgs
	if atomic.AddInt32(&rs.newR4pending, -1) == 0 {
		rs.round4New()
	}
}

func (rs *Resharing) onR3msg1New(from []*tss.PartyID, msgs []*resharingRound3msg1) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	rs.r3msg1From = from
	rs.r3msg1 = msgs
	if atomic.AddInt32(&rs.newR4pending, -1) == 0 {
		rs.round4New()
	}
}

func (rs *Resharing) onR3msg2New(from []*tss.PartyID, msgs []*resharingRound3msg2) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	rs.r3msg2From = from
	rs.r3msg2 = msgs
	if atomic.AddInt32(&rs.newR4pending, -1) == 0 {
		rs.round4New()
	}
}

// ---- Round 2 (Old committee receives ACK from new) ---- //

func (rs *Resharing) onR2msg2Old(from []*tss.PartyID, msgs []*resharingRound2msg2) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	// Old committee proceeds to round 3
	rs.round3Old()
}

// ---- Round 3 (Old committee sends VSS shares P2P + decommitment broadcast) ---- //

func (rs *Resharing) round3Old() {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	Pi := rs.params.PartyID()
	newIDs := rs.params.NewParties().IDs()

	// Send P2P shares to each new party
	for j, Pj := range newIDs {
		share := rs.newShares[j]
		r3msg1 := &resharingRound3msg1{
			Share: share.Share.Bytes(),
		}
		m := tss.JsonWrap("ecdsa:resharing:round3-1", r3msg1, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Broadcast decommitment to new committee
	r3msg2 := &resharingRound3msg2{
		VDecommitment: common.BigIntsToBytes(rs.vd),
	}
	for _, Pj := range newIDs {
		m := tss.JsonWrap("ecdsa:resharing:round3-2", r3msg2, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Old committee now waits for round 4 ACK from new committee
	r4m2rcv := tss.NewJsonExpect[resharingRound4msg2]("ecdsa:resharing:round4-2", newIDs, rs.onR4msg2Old)
	rs.params.Broker().Connect("ecdsa:resharing:round4-2", r4m2rcv)
}

// ---- Round 4 (New committee: verify proofs, compute new key shares, send FacProofs) ---- //

func (rs *Resharing) round4New() {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	Pi := rs.params.PartyID()
	ec := rs.params.EC()
	newIDs := rs.params.NewParties().IDs()
	oldIDs := rs.params.OldParties().IDs()

	// 1. Verify DLN proofs and ModProofs from other new committee members (r2msg1)
	h1H2Map := make(map[string]struct{}, (len(rs.r2msg1)+1)*2)
	dlnProof1Fail := make([]bool, len(rs.r2msg1))
	dlnProof2Fail := make([]bool, len(rs.r2msg1))
	paiProofFail := make([]bool, len(rs.r2msg1))
	wg := new(sync.WaitGroup)

	// Build index mapping for r2msg1 (new committee messages, excluding self)
	r2msg1IdxMap := make([]int, len(rs.r2msg1From))
	for k, oid := range rs.r2msg1From {
		for n, pid := range newIDs {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				r2msg1IdxMap[k] = n
				break
			}
		}
	}

	// Include self in h1H2Map
	selfH1Hex := hex.EncodeToString(rs.preParams.H1i.Bytes())
	selfH2Hex := hex.EncodeToString(rs.preParams.H2i.Bytes())
	h1H2Map[selfH1Hex] = struct{}{}
	h1H2Map[selfH2Hex] = struct{}{}

	for k, msg := range rs.r2msg1 {
		NTildej := new(big.Int).SetBytes(msg.NTilde)
		H1j := new(big.Int).SetBytes(msg.H1)
		H2j := new(big.Int).SetBytes(msg.H2)

		// Enforce a minimum bit length on the peer Paillier modulus N and NTilde
		// before storing/using them (parity with keygen). A short modulus weakens
		// the range/Mod proofs and the Paillier encryption itself.
		paillierN := new(big.Int).SetBytes(msg.PaillierN)
		if paillierN.BitLen() < paillierModulusLen {
			rs.Err <- fmt.Errorf("party %s: paillier modulus bit length %d < %d", rs.r2msg1From[k], paillierN.BitLen(), paillierModulusLen)
			return
		}
		if NTildej.BitLen() < paillierModulusLen {
			rs.Err <- fmt.Errorf("party %s: NTilde bit length %d < %d", rs.r2msg1From[k], NTildej.BitLen(), paillierModulusLen)
			return
		}

		if H1j.Cmp(H2j) == 0 {
			rs.Err <- fmt.Errorf("party %s: H1j == H2j", rs.r2msg1From[k])
			return
		}
		h1JHex := hex.EncodeToString(H1j.Bytes())
		h2JHex := hex.EncodeToString(H2j.Bytes())
		if _, found := h1H2Map[h1JHex]; found {
			rs.Err <- fmt.Errorf("party %s: h1j already used", rs.r2msg1From[k])
			return
		}
		if _, found := h1H2Map[h2JHex]; found {
			rs.Err <- fmt.Errorf("party %s: h2j already used", rs.r2msg1From[k])
			return
		}
		h1H2Map[h1JHex] = struct{}{}
		h1H2Map[h2JHex] = struct{}{}

		kk := k
		h1jCopy, h2jCopy, ntCopy := H1j, H2j, NTildej
		wg.Add(3)
		go func() {
			defer wg.Done()
			if rs.params.NoProofMod() {
				return
			}
			mp, err := modproof.NewProofFromBytes(rs.r2msg1[kk].ModProof)
			if err != nil {
				paiProofFail[kk] = true
				return
			}
			ContextJ := common.AppendBigIntToBytesSlice(rs.ssid, big.NewInt(int64(r2msg1IdxMap[kk])))
			paiPK := &paillier.PublicKey{N: new(big.Int).SetBytes(rs.r2msg1[kk].PaillierN)}
			if ok := mp.Verify(ContextJ, paiPK.N); !ok {
				paiProofFail[kk] = true
			}
		}()
		go func() {
			defer wg.Done()
			dlnPf1, err := dlnproof.UnmarshalDLNProof(rs.r2msg1[kk].Dlnproof_1)
			if err != nil || !dlnPf1.Verify(h1jCopy, h2jCopy, ntCopy) {
				dlnProof1Fail[kk] = true
			}
		}()
		go func() {
			defer wg.Done()
			dlnPf2, err := dlnproof.UnmarshalDLNProof(rs.r2msg1[kk].Dlnproof_2)
			if err != nil || !dlnPf2.Verify(h2jCopy, h1jCopy, ntCopy) {
				dlnProof2Fail[kk] = true
			}
		}()
	}
	wg.Wait()

	for k := range rs.r2msg1 {
		if paiProofFail[k] || dlnProof1Fail[k] || dlnProof2Fail[k] {
			rs.Err <- fmt.Errorf("party %s: DLN/ModProof verification failed", rs.r2msg1From[k])
			return
		}
	}

	// Save NTilde, H1, H2, PaillierPK from other new committee members
	for k, msg := range rs.r2msg1 {
		jIdx := r2msg1IdxMap[k]
		rs.newKey.NTildej[jIdx] = new(big.Int).SetBytes(msg.NTilde)
		rs.newKey.H1j[jIdx] = new(big.Int).SetBytes(msg.H1)
		rs.newKey.H2j[jIdx] = new(big.Int).SetBytes(msg.H2)
		rs.newKey.PaillierPKs[jIdx] = &paillier.PublicKey{N: new(big.Int).SetBytes(msg.PaillierN)}
	}

	// 2. Verify decommitments and VSS shares from old committee (R1 + R3 messages)
	// Build index maps for R1, R3msg1, R3msg2 (all from old committee)
	r1IdxMap := make(map[int]int) // position in r1msgs -> oldIDs index
	for k, oid := range rs.r1msgsFrom {
		for n, pid := range oldIDs {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				r1IdxMap[k] = n
				break
			}
		}
	}
	r3m1IdxMap := make(map[int]int)
	for k, oid := range rs.r3msg1From {
		for n, pid := range oldIDs {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				r3m1IdxMap[k] = n
				break
			}
		}
	}
	r3m2IdxMap := make(map[int]int)
	for k, oid := range rs.r3msg2From {
		for n, pid := range oldIDs {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				r3m2IdxMap[k] = n
				break
			}
		}
	}

	// Build lookup: oldPartyIdx -> message position
	r1ByOldIdx := make(map[int]int)
	for k, idx := range r1IdxMap {
		r1ByOldIdx[idx] = k
	}
	r3m2ByOldIdx := make(map[int]int)
	for k, idx := range r3m2IdxMap {
		r3m2ByOldIdx[idx] = k
	}

	newXi := big.NewInt(0)
	modQ := common.ModInt(ec.Params().N)
	vjc := make([][]*crypto.ECPoint, len(oldIDs))

	for k, r3m1 := range rs.r3msg1 {
		jOldIdx := r3m1IdxMap[k]

		r1Pos, ok := r1ByOldIdx[jOldIdx]
		if !ok {
			rs.Err <- fmt.Errorf("missing R1 message for old party index %d", jOldIdx)
			return
		}
		r3m2Pos, ok := r3m2ByOldIdx[jOldIdx]
		if !ok {
			rs.Err <- fmt.Errorf("missing R3 decommitment for old party index %d", jOldIdx)
			return
		}

		r1msg := rs.r1msgs[r1Pos]
		r3m2 := rs.r3msg2[r3m2Pos]

		vCj := cmts.HashCommitment(new(big.Int).SetBytes(r1msg.VCommitment))
		vDj := cmts.NewHashDeCommitmentFromBytes(r3m2.VDecommitment)

		// Verify decommitment
		vCmtDeCmt := cmts.HashCommitDecommit{C: vCj, D: vDj}
		ok2, flatVs := vCmtDeCmt.DeCommit()
		if !ok2 || len(flatVs) != (rs.params.NewThreshold()+1)*2 {
			rs.Err <- fmt.Errorf("de-commitment verification failed for old party %s", rs.r3msg1From[k])
			return
		}
		vj, err := crypto.UnFlattenECPoints(ec, flatVs)
		if err != nil {
			rs.Err <- fmt.Errorf("UnFlattenECPoints failed for old party %s: %w", rs.r3msg1From[k], err)
			return
		}
		vjc[jOldIdx] = vj

		// Verify VSS share
		sharej := &vss.Share{
			Threshold: rs.params.NewThreshold(),
			ID:        Pi.KeyInt(),
			Share:     new(big.Int).SetBytes(r3m1.Share),
		}
		if ok3 := sharej.Verify(ec, rs.params.NewThreshold(), vj); !ok3 {
			rs.Err <- fmt.Errorf("VSS share verification failed for old party %s", rs.r3msg1From[k])
			return
		}

		newXi = new(big.Int).Add(newXi, sharej.Share)
	}

	// Compute Vc (aggregated VSS coefficients)
	Vc := make([]*crypto.ECPoint, rs.params.NewThreshold()+1)
	for c := 0; c <= rs.params.NewThreshold(); c++ {
		var first *crypto.ECPoint
		for j := 0; j < len(oldIDs); j++ {
			if vjc[j] == nil {
				continue
			}
			if first == nil {
				first = vjc[j][c]
			} else {
				var err error
				first, err = first.Add(vjc[j][c])
				if err != nil {
					rs.Err <- fmt.Errorf("Vc[%d] aggregation failed: %w", c, err)
					return
				}
			}
		}
		Vc[c] = first
	}

	// Verify V_0 == ECDSAPub
	if !Vc[0].Equals(rs.newKey.ECDSAPub) {
		rs.Err <- errors.New("assertion failed: V_0 != ECDSAPub")
		return
	}

	// Compute newBigXjs and newKs for each new party
	newKs := make([]*big.Int, 0, rs.params.NewPartyCount())
	newBigXjs := make([]*crypto.ECPoint, rs.params.NewPartyCount())
	for j := 0; j < rs.params.NewPartyCount(); j++ {
		Pj := newIDs[j]
		kj := Pj.KeyInt()
		newKs = append(newKs, kj)
		newBigXj := Vc[0]
		z := new(big.Int).SetInt64(1)
		for c := 1; c <= rs.params.NewThreshold(); c++ {
			z = modQ.Mul(z, kj)
			var err error
			newBigXj, err = newBigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				rs.Err <- fmt.Errorf("newBigXj computation failed: %w", err)
				return
			}
		}
		newBigXjs[j] = newBigXj
	}

	rs.newXi = newXi
	rs.newKs = newKs
	rs.newBigXjs = newBigXjs

	// Send FacProof to each other new party (P2P)
	for _, Pj := range newIDs {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		var jIdx int
		for n, pid := range newIDs {
			if pid.KeyInt().Cmp(Pj.KeyInt()) == 0 {
				jIdx = n
				break
			}
		}

		ContextJ := common.AppendBigIntToBytesSlice(rs.ssid, big.NewInt(int64(jIdx)))
		facProofObj := &facproof.ProofFac{
			P: zero, Q: zero, A: zero, B: zero, T: zero, Sigma: zero,
			Z1: zero, Z2: zero, W1: zero, W2: zero, V: zero,
		}
		if !rs.params.NoProofFac() {
			var err error
			facProofObj, err = facproof.NewProof(ContextJ, ec, rs.newKey.PaillierSK.N,
				rs.newKey.NTildej[jIdx], rs.newKey.H1j[jIdx], rs.newKey.H2j[jIdx],
				rs.newKey.PaillierSK.P, rs.newKey.PaillierSK.Q, rs.params.Rand())
			if err != nil {
				rs.Err <- fmt.Errorf("FacProof generation failed: %w", err)
				return
			}
		}
		pfBzs := facProofObj.Bytes()
		r4msg1 := &resharingRound4msg1{
			FacProof: pfBzs[:],
		}
		m := tss.JsonWrap("ecdsa:resharing:round4-1", r4msg1, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Broadcast ACK to both old and new committees
	r4msg2 := &resharingRound4msg2{}
	allIDs := append(rs.params.OldParties().IDs(), newIDs...)
	for _, Pj := range allIDs {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue // don't send to self
		}
		m := tss.JsonWrap("ecdsa:resharing:round4-2", r4msg2, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// Wait for FacProofs from other new members (P2P) + ACKs from other new members (broadcast)
	var otherNewIDs []*tss.PartyID
	for _, Pj := range newIDs {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		otherNewIDs = append(otherNewIDs, Pj)
	}

	atomic.StoreInt32(&rs.newR5pending, 2)

	r4m1rcv := tss.NewJsonExpect[resharingRound4msg1]("ecdsa:resharing:round4-1", otherNewIDs, rs.onR4msg1New)
	rs.params.Broker().Connect("ecdsa:resharing:round4-1", r4m1rcv)

	r4m2rcv := tss.NewJsonExpect[resharingRound4msg2]("ecdsa:resharing:round4-2", otherNewIDs, rs.onR4msg2New)
	rs.params.Broker().Connect("ecdsa:resharing:round4-2", r4m2rcv)
}

func (rs *Resharing) onR4msg1New(from []*tss.PartyID, msgs []*resharingRound4msg1) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	rs.r4msg1From = from
	rs.r4msg1 = msgs
	if atomic.AddInt32(&rs.newR5pending, -1) == 0 {
		rs.round5New()
	}
}

func (rs *Resharing) onR4msg2New(from []*tss.PartyID, msgs []*resharingRound4msg2) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	rs.r4msg2From = from
	rs.r4msg2 = msgs
	if atomic.AddInt32(&rs.newR5pending, -1) == 0 {
		rs.round5New()
	}
}

// ---- Round 4 (Old committee receives ACK from new committee) ---- //

func (rs *Resharing) onR4msg2Old(from []*tss.PartyID, msgs []*resharingRound4msg2) {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	// Old committee: zero out Xi and finish
	rs.input.Xi.SetInt64(0)
	rs.Done <- rs.input
}

// ---- Round 5 (New committee: verify FacProofs and save) ---- //

func (rs *Resharing) round5New() {
	if rs.ctx.Err() != nil {
		rs.Err <- rs.ctx.Err()
		return
	}
	i := rs.params.PartyID().Index

	ContextI := append(rs.ssid, big.NewInt(int64(i)).Bytes()...)

	// Save key data
	rs.newKey.BigXj = rs.newBigXjs
	rs.newKey.ShareID = rs.params.PartyID().KeyInt()
	rs.newKey.Xi = rs.newXi
	rs.newKey.Ks = rs.newKs

	// Verify FacProofs from other new committee members
	newIDs := rs.params.NewParties().IDs()
	for k, msg := range rs.r4msg1 {
		var jIdx int
		for n, pid := range newIDs {
			if pid.KeyInt().Cmp(rs.r4msg1From[k].KeyInt()) == 0 {
				jIdx = n
				break
			}
		}

		if !rs.params.NoProofFac() {
			proof, err := facproof.NewProofFromBytes(msg.FacProof)
			if err != nil {
				rs.Err <- fmt.Errorf("FacProof deserialization failed for party %s: %w", rs.r4msg1From[k], err)
				return
			}
			if ok := proof.Verify(ContextI, rs.params.EC(), rs.newKey.PaillierPKs[jIdx].N,
				rs.newKey.NTildei, rs.newKey.H1i, rs.newKey.H2i); !ok {
				rs.Err <- fmt.Errorf("FacProof verification failed for party %s", rs.r4msg1From[k])
				return
			}
		}
	}

	rs.Done <- rs.newKey
}
