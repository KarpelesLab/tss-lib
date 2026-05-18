package eddsatss

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	cmts "github.com/KarpelesLab/tss-lib/v2/crypto/commitments"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Keygen tracks a key currently being generated via the EdDSA TSS protocol.
type Keygen struct {
	ctx           context.Context
	params        *tss.Parameters
	KGCs          []cmts.HashCommitment
	vs            vss.Vs
	shares        vss.Shares
	deCommitPolyG cmts.HashDeCommitment
	ssid          []byte
	ssidNonce     *big.Int
	ui            *big.Int // kept for Schnorr proof in round 2
	data          *Key

	Done chan *Key
	Err  chan error
}

// NewKeygen creates a new Keygen instance and kicks off round 1 of the EdDSA key generation protocol.
func NewKeygen(ctx context.Context, params *tss.Parameters) (*Keygen, error) {
	partyCount := params.PartyCount()
	kg := &Keygen{
		ctx:    ctx,
		params: params,
		KGCs:   make([]cmts.HashCommitment, partyCount),
		data:   NewKey(partyCount),
		Done:   make(chan *Key, 1),
		Err:    make(chan error, 1),
	}
	err := kg.round1()
	if err != nil {
		return nil, err
	}
	return kg, nil
}

// getSSID returns ssid from local params.
func (kg *Keygen) getSSID(roundNum int) ([]byte, error) {
	ssidList := []*big.Int{
		kg.params.EC().Params().P,
		kg.params.EC().Params().N,
		kg.params.EC().Params().Gx,
		kg.params.EC().Params().Gy,
	}
	ssidList = append(ssidList, kg.params.Parties().IDs().Keys()...)
	ssidList = append(ssidList, big.NewInt(int64(roundNum)))
	ssidList = append(ssidList, kg.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()
	return ssid, nil
}

func (kg *Keygen) round1() error {
	Pi := kg.params.PartyID()
	i := Pi.Index

	// 1. calculate "partial" key share ui
	ui := common.GetRandomPositiveInt(kg.params.PartialKeyRand(), kg.params.EC().Params().N)

	// 2. compute the vss shares
	ids := kg.params.Parties().IDs().Keys()
	vs, shares, err := vss.Create(kg.params.EC(), kg.params.Threshold(), ui, ids, kg.params.Rand())
	if err != nil {
		return err
	}
	kg.data.Ks = ids

	// NOTE: In EdDSA we keep ui for the Schnorr proof in round 2 (unlike ECDSA which discards it).
	kg.ui = ui

	// 3. make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return err
	}
	cmt := cmts.NewHashCommitment(kg.params.Rand(), pGFlat...)

	// ssidNonce is hard-coded to 0 because every party computes ssid
	// independently and must produce the same value: a per-party random
	// nonce would diverge across parties and break the Fiat-Shamir
	// challenge in the round-2 Schnorr PoK (each verifier uses its own
	// ssid; mismatched contexts produce different challenges and rejection).
	//
	// To gain per-session uniqueness without breaking verification, all
	// parties would need to agree on a nonce out of band or derive it
	// deterministically from the round-1 commitments before round 2's
	// PoK construction. That is a protocol redesign beyond a one-line
	// fix; the Fiat-Shamir challenge already depends on the prover's
	// fresh Alpha so PoK soundness holds across replays — only the
	// transcript-level binding to "session identity" is weakened by the
	// static nonce.
	kg.ssidNonce = new(big.Int).SetUint64(0)
	kg.data.ShareID = ids[i]
	kg.vs = vs
	kg.shares = shares
	kg.deCommitPolyG = cmt.D

	kg.ssid, err = kg.getSSID(1)
	if err != nil {
		return errors.New("failed to generate ssid")
	}

	// build list of other party IDs
	var otherIds []*tss.PartyID
	for n, p := range kg.params.Parties().IDs() {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	// broadcast round 1 message: commitment
	msg := &keygenRound1msg{
		Commitment: cmt.C.Bytes(),
	}
	for _, p := range otherIds {
		m := tss.JsonWrap("eddsa:keygen:round1", msg, Pi, p)
		kg.params.Broker().Receive(m)
	}

	// register receiver for round 1 messages from others -> triggers round 2
	rcv := tss.NewJsonExpect[keygenRound1msg]("eddsa:keygen:round1", otherIds, kg.round2)
	kg.params.Broker().Connect("eddsa:keygen:round1", rcv)

	return nil
}

func (kg *Keygen) round2(otherIds []*tss.PartyID, r1msgs []*keygenRound1msg) {
	if kg.ctx.Err() != nil {
		kg.Err <- kg.ctx.Err()
		return
	}
	Pi := kg.params.PartyID()
	i := Pi.Index

	// store commitments from round 1 messages
	for n, pid := range otherIds {
		// find the index in parties by matching the key
		for j, Pj := range kg.params.Parties().IDs() {
			if Pj.KeyInt().Cmp(pid.KeyInt()) == 0 {
				kg.KGCs[j] = new(big.Int).SetBytes(r1msgs[n].Commitment)
				break
			}
		}
	}

	// p2p send share to each other party
	for _, Pj := range otherIds {
		// find the correct share for this party by matching share IDs
		var shareForPj *big.Int
		for _, sh := range kg.shares {
			if sh.ID.Cmp(Pj.KeyInt()) == 0 {
				shareForPj = sh.Share
				break
			}
		}
		if shareForPj == nil {
			kg.Err <- fmt.Errorf("could not find share for party %s", Pj)
			return
		}
		r2msg1 := &keygenRound2msg1{
			Share: shareForPj.Bytes(),
		}
		m := tss.JsonWrap("eddsa:keygen:round2-1", r2msg1, Pi, Pj)
		kg.params.Broker().Receive(m)
	}

	// compute Schnorr proof: prove knowledge of ui such that vs[0] = ui*G
	ContextI := append(kg.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)
	pii, err := schnorr.NewZKProof(ContextI, kg.ui, kg.vs[0], kg.params.Rand())
	if err != nil {
		kg.Err <- fmt.Errorf("NewZKProof(ui, vi0): %w", err)
		return
	}

	// broadcast decommitment + Schnorr proof
	r2msg2 := &keygenRound2msg2{
		DeCommitment:       common.BigIntsToBytes(kg.deCommitPolyG),
		SchnorrProofAlphaX: pii.Alpha.X().Bytes(),
		SchnorrProofAlphaY: pii.Alpha.Y().Bytes(),
		SchnorrProofT:      pii.T.Bytes(),
	}
	for _, p := range otherIds {
		m := tss.JsonWrap("eddsa:keygen:round2-2", r2msg2, Pi, p)
		kg.params.Broker().Receive(m)
	}

	// security: now we can discard ui
	kg.ui = nil

	// register two receivers (round2-1 P2P shares, round2-2 broadcast decommit+proof)
	// use atomic counter to track completion of both
	var counter int32
	var r2msg1s []*keygenRound2msg1
	var r2msg2s []*keygenRound2msg2

	check := func() {
		if atomic.AddInt32(&counter, 1) == 2 {
			kg.processRound3(otherIds, r2msg1s, r2msg2s)
		}
	}

	rcv1 := tss.NewJsonExpect[keygenRound2msg1]("eddsa:keygen:round2-1", otherIds, func(ids []*tss.PartyID, msgs []*keygenRound2msg1) {
		r2msg1s = msgs
		check()
	})
	kg.params.Broker().Connect("eddsa:keygen:round2-1", rcv1)

	rcv2 := tss.NewJsonExpect[keygenRound2msg2]("eddsa:keygen:round2-2", otherIds, func(ids []*tss.PartyID, msgs []*keygenRound2msg2) {
		r2msg2s = msgs
		check()
	})
	kg.params.Broker().Connect("eddsa:keygen:round2-2", rcv2)
}

func (kg *Keygen) processRound3(otherIds []*tss.PartyID, r2msg1s []*keygenRound2msg1, r2msg2s []*keygenRound2msg2) {
	if kg.ctx.Err() != nil {
		kg.Err <- kg.ctx.Err()
		return
	}
	ec := kg.params.EC()
	PIdx := kg.params.PartyID().Index

	// verify each other party's decommitment, Schnorr proof, and VSS share
	type vssOut struct {
		err  error
		pjVs vss.Vs
	}

	chs := make([]chan vssOut, len(otherIds))
	for n := range otherIds {
		chs[n] = make(chan vssOut, 1)
	}

	for n, pid := range otherIds {
		go func(n int, pid *tss.PartyID) {
			// find the index j for this party in the main party list
			j := -1
			for idx, Pj := range kg.params.Parties().IDs() {
				if Pj.KeyInt().Cmp(pid.KeyInt()) == 0 {
					j = idx
					break
				}
			}
			if j == -1 {
				chs[n] <- vssOut{errors.New("party not found"), nil}
				return
			}

			ContextJ := common.AppendBigIntToBytesSlice(kg.ssid, big.NewInt(int64(j)))

			// 1. verify decommitment
			KGCj := kg.KGCs[j]
			KGDj := cmts.NewHashDeCommitmentFromBytes(r2msg2s[n].DeCommitment)
			cmtDeCmt := cmts.HashCommitDecommit{C: KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit()
			if !ok || flatPolyGs == nil {
				chs[n] <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}

			// 2. unflatten EC points
			PjVs, err := crypto.UnFlattenECPoints(ec, flatPolyGs)
			if err != nil {
				chs[n] <- vssOut{err, nil}
				return
			}

			// 3. apply EightInvEight to each point
			for idx, PjV := range PjVs {
				PjVs[idx] = PjV.EightInvEight()
			}

			// 4. verify Schnorr proof
			alphaX := new(big.Int).SetBytes(r2msg2s[n].SchnorrProofAlphaX)
			alphaY := new(big.Int).SetBytes(r2msg2s[n].SchnorrProofAlphaY)
			alpha, err := crypto.NewECPoint(ec, alphaX, alphaY)
			if err != nil {
				chs[n] <- vssOut{errors.New("failed to reconstruct Schnorr proof alpha point"), nil}
				return
			}
			proof := &schnorr.ZKProof{
				Alpha: alpha,
				T:     new(big.Int).SetBytes(r2msg2s[n].SchnorrProofT),
			}
			if !proof.Verify(ContextJ, PjVs[0]) {
				chs[n] <- vssOut{errors.New("Schnorr proof verification failed"), nil}
				return
			}

			// 5. verify VSS share
			shareFromJ := new(big.Int).SetBytes(r2msg1s[n].Share)
			PjShare := vss.Share{
				Threshold: kg.params.Threshold(),
				ID:        kg.data.ShareID,
				Share:     shareFromJ,
			}
			if !PjShare.Verify(ec, kg.params.Threshold(), PjVs) {
				chs[n] <- vssOut{errors.New("VSS share verification failed"), nil}
				return
			}

			chs[n] <- vssOut{nil, PjVs}
		}(n, pid)
	}

	// collect results
	vssResults := make([]vssOut, len(otherIds))
	for n := range otherIds {
		vssResults[n] = <-chs[n]
		if vssResults[n].err != nil {
			kg.Err <- vssResults[n].err
			return
		}
	}

	// compute xi = ownShare + sum(receivedShares) mod N
	xi := new(big.Int).Set(kg.shares[PIdx].Share)
	for n := range otherIds {
		shareFromJ := new(big.Int).SetBytes(r2msg1s[n].Share)
		xi = new(big.Int).Add(xi, shareFromJ)
	}
	kg.data.Xi = new(big.Int).Mod(xi, ec.Params().N)

	// aggregate Vc: Vc[c] = vs[c] + sum(PjVs[c])
	Vc := make(vss.Vs, kg.params.Threshold()+1)
	for c := range Vc {
		Vc[c] = kg.vs[c]
	}
	for n := range otherIds {
		PjVs := vssResults[n].pjVs
		for c := 0; c <= kg.params.Threshold(); c++ {
			var err error
			Vc[c], err = Vc[c].Add(PjVs[c])
			if err != nil {
				kg.Err <- fmt.Errorf("adding PjVs[c] to Vc[c] failed: %w", err)
				return
			}
		}
	}

	// compute BigXj for each party: evaluate polynomial at each party's key
	modQ := common.ModInt(ec.Params().N)
	for j := 0; j < kg.params.PartyCount(); j++ {
		kj := kg.params.Parties().IDs()[j].KeyInt()
		BigXj := Vc[0]
		z := new(big.Int).SetInt64(1)
		for c := 1; c <= kg.params.Threshold(); c++ {
			z = modQ.Mul(z, kj)
			var err error
			BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				kg.Err <- fmt.Errorf("computing BigXj failed: %w", err)
				return
			}
		}
		kg.data.BigXj[j] = BigXj
	}

	// EDDSAPub = Vc[0]
	eddsaPubKey, err := crypto.NewECPoint(ec, Vc[0].X(), Vc[0].Y())
	if err != nil {
		kg.Err <- fmt.Errorf("public key is not on the curve: %w", err)
		return
	}
	kg.data.EDDSAPub = eddsaPubKey

	kg.Done <- kg.data
}
