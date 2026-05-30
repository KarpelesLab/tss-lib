package ecdsatss

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	cmts "github.com/KarpelesLab/tss-lib/v2/crypto/commitments"
	"github.com/KarpelesLab/tss-lib/v2/crypto/mta"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Signing tracks a threshold ECDSA signing operation.
type Signing struct {
	ctx    context.Context
	params *tss.Parameters
	key    *Key

	// round 1
	w, m, k, gamma *big.Int
	pointGamma     *crypto.ECPoint
	deCommit       cmts.HashDeCommitment
	cis            []*big.Int        // Paillier ciphertexts from AliceInit
	bigWs          []*crypto.ECPoint // transformed BigXj with Lagrange coefficients

	// round 2
	betas []*big.Int
	c1jis []*big.Int
	c2jis []*big.Int
	vs    []*big.Int

	// round 3
	theta *big.Int
	sigma *big.Int

	// round 4
	thetaInverse *big.Int

	// round 5
	si, rx, ry *big.Int
	li, roi    *big.Int
	bigR       *crypto.ECPoint
	bigAi      *crypto.ECPoint
	bigVi      *crypto.ECPoint
	r5DeCommit cmts.HashDeCommitment

	// round 7
	Ui, Ti     *crypto.ECPoint
	r7DeCommit cmts.HashDeCommitment

	// ssid
	ssid      []byte
	ssidNonce *big.Int

	// synchronization for dual-message rounds
	r1pending int32

	// received message storage for round 1 (dual message)
	r1msg1From []*tss.PartyID
	r1msg1     []*signRound1msg1
	r1msg2From []*tss.PartyID
	r1msg2     []*signRound1msg2

	// stored commitments from round 1 msg2 (indexed by party)
	r1Commitments []*big.Int

	// stored commitments from round 5 (indexed by party)
	r5Commitments []*big.Int

	// stored commitments from round 7 (indexed by party)
	r7Commitments []*big.Int

	Done chan *SignatureData
	Err  chan error
}

// NewSigning creates a new Signing instance and kicks off round 1 of the ECDSA signing protocol.
//
// The receiver key may have been produced by a keygen that involved more parties than the
// current signing committee; NewSigning transparently reindexes the per-party slices (Ks,
// NTildej, H1j, H2j, BigXj, PaillierPKs) to match params.Parties().IDs() via
// SubsetForParties, so callers can pass the full keygen key as-is.
func (key *Key) NewSigning(ctx context.Context, msg *big.Int, params *tss.Parameters) (*Signing, error) {
	// Validate the message scalar before doing any work. A nil msg would panic on
	// first use; a negative msg passes the "< N" test but msg.Bytes() drops the
	// sign, producing confusing aborts later. Require 0 < msg < N.
	if msg == nil {
		return nil, errors.New("message to sign is nil")
	}
	if msg.Sign() <= 0 {
		return nil, errors.New("message to sign must be positive")
	}
	if msg.Cmp(params.EC().Params().N) >= 0 {
		return nil, errors.New("message to sign is not less than the curve order")
	}
	subsetKey, err := key.SubsetForParties(params.Parties().IDs())
	if err != nil {
		return nil, err
	}
	// Verify the local secret share matches the public share at this party's
	// index: Xi·G == BigXj[localIdx]. SubsetForParties already verified that the
	// BigXj interpolate to ECDSAPub; this ties our private Xi to that set.
	localIdx := params.PartyID().Index
	if localIdx < 0 || localIdx >= len(subsetKey.BigXj) {
		return nil, fmt.Errorf("local party index %d out of range", localIdx)
	}
	if subsetKey.Xi == nil {
		return nil, errors.New("local secret share Xi is nil")
	}
	if !crypto.ScalarBaseMult(params.EC(), subsetKey.Xi).Equals(subsetKey.BigXj[localIdx]) {
		return nil, errors.New("local secret share Xi is inconsistent with BigXj[localIdx]")
	}
	partyCount := params.PartyCount()
	s := &Signing{
		ctx:           ctx,
		params:        params,
		key:           subsetKey,
		m:             msg,
		cis:           make([]*big.Int, partyCount),
		bigWs:         make([]*crypto.ECPoint, partyCount),
		betas:         make([]*big.Int, partyCount),
		c1jis:         make([]*big.Int, partyCount),
		c2jis:         make([]*big.Int, partyCount),
		vs:            make([]*big.Int, partyCount),
		r1Commitments: make([]*big.Int, partyCount),
		r5Commitments: make([]*big.Int, partyCount),
		r7Commitments: make([]*big.Int, partyCount),
		Done:          make(chan *SignatureData, 1),
		Err:           make(chan error, 1),
	}
	if err := s.round1(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewSigningWithKDD is a drop-in replacement for NewSigning that signs under a BIP32-derived
// child key. The master key is left untouched: a clone is shifted by keyDerivationDelta and
// then signed with. ECDSAPub and every BigXj[j] are offset by delta·G, and the local share Xi
// has delta added modulo the curve order — the threshold signature will verify under the
// derived child public key (master.ECDSAPub + delta·G).
//
// A nil keyDerivationDelta short-circuits to NewSigning.
func (key *Key) NewSigningWithKDD(ctx context.Context, msg *big.Int, params *tss.Parameters, keyDerivationDelta *big.Int) (*Signing, error) {
	if keyDerivationDelta == nil {
		return key.NewSigning(ctx, msg, params)
	}

	keyClone := *key
	keyClone.BigXj = slices.Clone(key.BigXj)

	deltaG := crypto.ScalarBaseMult(key.ECDSAPub.Curve(), keyDerivationDelta)

	newPub, err := deltaG.Add(key.ECDSAPub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child ECDSAPub: %w", err)
	}
	keyClone.ECDSAPub = newPub

	// Adding delta to the shared secret shifts every Shamir share by the same delta,
	// so BigXj[j] becomes BigXj[j] + delta·G for every party.
	for j := range keyClone.BigXj {
		shifted, err := key.BigXj[j].Add(deltaG)
		if err != nil {
			return nil, fmt.Errorf("failed to shift BigXj[%d]: %w", j, err)
		}
		keyClone.BigXj[j] = shifted
	}

	modQ := common.ModInt(params.EC().Params().N)
	keyClone.Xi = modQ.Add(keyDerivationDelta, key.Xi)

	return (&keyClone).NewSigning(ctx, msg, params)
}

// getSSID returns ssid from local params, including BigXj and NTilde/h1/h2 in the hash.
func (s *Signing) getSSID() ([]byte, error) {
	ec := s.params.EC()
	ssidList := []*big.Int{ec.Params().P, ec.Params().N, ec.Params().B, ec.Params().Gx, ec.Params().Gy}
	ssidList = append(ssidList, s.params.Parties().IDs().Keys()...)
	BigXjList, err := crypto.FlattenECPoints(s.key.BigXj)
	if err != nil {
		return nil, fmt.Errorf("read BigXj failed: %w", err)
	}
	ssidList = append(ssidList, BigXjList...)
	ssidList = append(ssidList, s.key.NTildej...)
	ssidList = append(ssidList, s.key.H1j...)
	ssidList = append(ssidList, s.key.H2j...)
	ssidList = append(ssidList, big.NewInt(1)) // round number for signing
	ssidList = append(ssidList, s.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()
	return ssid, nil
}

// prepareForSigning computes the Lagrange coefficient wi and the transformed bigWs.
func (s *Signing) prepareForSigning() error {
	i := s.params.PartyID().Index
	ec := s.params.EC()

	xi := s.key.Xi
	ks := s.key.Ks
	bigXs := s.key.BigXj

	if s.params.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", s.params.Threshold()+1, len(ks))
	}

	// Use the PrepareForSigning from the ecdsa/signing package pattern
	modQ := common.ModInt(ec.Params().N)
	pax := len(ks)

	if len(ks) != len(bigXs) {
		return fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(bigXs))
	}
	if pax <= i {
		return fmt.Errorf("PrepareForSigning: pax <= i (%d <= %d)", pax, i)
	}

	// Compute wi
	wi := new(big.Int).Set(xi)
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			return fmt.Errorf("index of two parties are equal")
		}
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}

	// Compute bigWs
	bigWs := make([]*crypto.ECPoint, pax)
	for j := 0; j < pax; j++ {
		bigWj := bigXs[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc := ks[c]
			ksj := ks[j]
			if ksj.Cmp(ksc) == 0 {
				return fmt.Errorf("index of two parties are equal")
			}
			iota := modQ.Mul(ksc, modQ.ModInverse(new(big.Int).Sub(ksc, ksj)))
			bigWj = bigWj.ScalarMult(iota)
		}
		bigWs[j] = bigWj
	}

	s.w = wi
	s.bigWs = bigWs
	return nil
}

func (s *Signing) round1() error {
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()

	// Validate message: require 0 < m < N. nil/non-positive values are rejected
	// in NewSigning, but re-check here as defense in depth before first use.
	if s.m == nil || s.m.Sign() <= 0 || s.m.Cmp(ec.Params().N) >= 0 {
		return errors.New("hashed message is not valid")
	}

	// Initialize ssid
	s.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	s.ssid, err = s.getSSID()
	if err != nil {
		return fmt.Errorf("failed to generate ssid: %w", err)
	}

	// Prepare for signing (Lagrange coefficients)
	if err := s.prepareForSigning(); err != nil {
		return err
	}

	// Generate random k, gamma
	k := common.GetRandomPositiveInt(s.params.Rand(), ec.Params().N)
	gamma := common.GetRandomPositiveInt(s.params.Rand(), ec.Params().N)

	// Compute pointGamma = gamma * G
	pointGamma := crypto.ScalarBaseMult(ec, gamma)

	// Create commitment to pointGamma
	cmt := cmts.NewHashCommitment(s.params.Rand(), pointGamma.X(), pointGamma.Y())

	s.k = k
	s.gamma = gamma
	s.pointGamma = pointGamma
	s.deCommit = cmt.D

	// Build list of other party IDs
	var otherIds []*tss.PartyID
	for n, p := range s.params.Parties().IDs() {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	// For each other party j: AliceInit to create Paillier ciphertext and range proof
	for _, Pj := range otherIds {
		j := Pj.Index
		cA, piA, err := mta.AliceInit(
			ec,
			s.key.PaillierPKs[i],
			k,
			s.key.NTildej[j],
			s.key.H1j[j],
			s.key.H2j[j],
			s.params.Rand(),
		)
		if err != nil {
			return fmt.Errorf("failed to init mta: %w", err)
		}
		s.cis[j] = cA

		pfBz := piA.Bytes()
		r1m1 := &signRound1msg1{
			C:               cA.Bytes(),
			RangeProofAlice: pfBz[:],
		}
		m := tss.JsonWrap("ecdsa:sign:round1-1", r1m1, Pi, Pj)
		s.params.Broker().Receive(m)
	}

	// Broadcast commitment (round1-2)
	r1m2 := &signRound1msg2{
		Commitment: cmt.C.Bytes(),
	}
	for _, Pj := range otherIds {
		m := tss.JsonWrap("ecdsa:sign:round1-2", r1m2, Pi, Pj)
		s.params.Broker().Receive(m)
	}

	// Set pending counter for two incoming message types
	atomic.StoreInt32(&s.r1pending, 2)

	// Register receivers for both round 1 message types
	rcv1 := tss.NewJsonExpect[signRound1msg1]("ecdsa:sign:round1-1", otherIds, s.onR1msg1)
	s.params.Broker().Connect("ecdsa:sign:round1-1", rcv1)

	rcv2 := tss.NewJsonExpect[signRound1msg2]("ecdsa:sign:round1-2", otherIds, s.onR1msg2)
	s.params.Broker().Connect("ecdsa:sign:round1-2", rcv2)

	return nil
}

func (s *Signing) onR1msg1(from []*tss.PartyID, msgs []*signRound1msg1) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	s.r1msg1From = from
	s.r1msg1 = msgs
	if atomic.AddInt32(&s.r1pending, -1) == 0 {
		s.round2()
	}
}

func (s *Signing) onR1msg2(from []*tss.PartyID, msgs []*signRound1msg2) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	s.r1msg2From = from
	s.r1msg2 = msgs
	if atomic.AddInt32(&s.r1pending, -1) == 0 {
		s.round2()
	}
}

func (s *Signing) round2() {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()
	allParties := s.params.Parties().IDs()

	// Store commitments from round 1 msg2
	for n, pid := range s.r1msg2From {
		for j, Pj := range allParties {
			if Pj.KeyInt().Cmp(pid.KeyInt()) == 0 {
				s.r1Commitments[j] = new(big.Int).SetBytes(s.r1msg2[n].Commitment)
				break
			}
		}
	}

	// Build index mapping: r1msg1From position -> allParties index
	msg1IdxMap := make(map[int]int)
	for k, oid := range s.r1msg1From {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				msg1IdxMap[k] = n
				break
			}
		}
	}

	ContextI := append(s.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)

	// For each other party j, perform BobMid and BobMidWC concurrently.
	// Store proof bytes for sending messages after all goroutines complete.
	type bobResult struct {
		j          int
		proofBob   [][]byte
		proofBobWC [][]byte
	}

	results := make([]bobResult, len(s.r1msg1From))
	errChs := make(chan error, len(s.r1msg1From)*2)
	wg := sync.WaitGroup{}
	wg.Add(len(s.r1msg1From) * 2)

	for idx := range s.r1msg1From {
		j := msg1IdxMap[idx]
		results[idx].j = j

		// BobMid (gamma * k_j)
		go func(idx, j int) {
			defer wg.Done()
			rangeProof, err := mta.RangeProofAliceFromBytes(s.r1msg1[idx].RangeProofAlice)
			if err != nil {
				errChs <- fmt.Errorf("party %d: RangeProofAliceFromBytes failed: %w", j, err)
				return
			}
			cA := new(big.Int).SetBytes(s.r1msg1[idx].C)
			beta, c1ji, _, pi1ji, err := mta.BobMid(
				ContextI,
				ec,
				s.key.PaillierPKs[j],
				rangeProof,
				s.gamma,
				cA,
				s.key.NTildej[j],
				s.key.H1j[j],
				s.key.H2j[j],
				s.key.NTildej[i],
				s.key.H1j[i],
				s.key.H2j[i],
				s.params.Rand(),
			)
			if err != nil {
				errChs <- fmt.Errorf("party %d: BobMid failed: %w", j, err)
				return
			}
			s.betas[j] = beta
			s.c1jis[j] = c1ji
			pfBob := pi1ji.Bytes()
			results[idx].proofBob = pfBob[:]
		}(idx, j)

		// BobMidWC (w * k_j)
		go func(idx, j int) {
			defer wg.Done()
			rangeProof, err := mta.RangeProofAliceFromBytes(s.r1msg1[idx].RangeProofAlice)
			if err != nil {
				errChs <- fmt.Errorf("party %d: RangeProofAliceFromBytes (WC) failed: %w", j, err)
				return
			}
			cA := new(big.Int).SetBytes(s.r1msg1[idx].C)
			v, c2ji, _, pi2ji, err := mta.BobMidWC(
				ContextI,
				ec,
				s.key.PaillierPKs[j],
				rangeProof,
				s.w,
				cA,
				s.key.NTildej[j],
				s.key.H1j[j],
				s.key.H2j[j],
				s.key.NTildej[i],
				s.key.H1j[i],
				s.key.H2j[i],
				s.bigWs[i],
				s.params.Rand(),
			)
			if err != nil {
				errChs <- fmt.Errorf("party %d: BobMidWC failed: %w", j, err)
				return
			}
			s.vs[j] = v
			s.c2jis[j] = c2ji
			pfBobWC := pi2ji.Bytes()
			results[idx].proofBobWC = pfBobWC[:]
		}(idx, j)
	}

	wg.Wait()
	close(errChs)
	for err := range errChs {
		if err != nil {
			s.Err <- err
			return
		}
	}

	// Send round 2 P2P messages
	var otherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	for _, res := range results {
		j := res.j
		Pj := allParties[j]

		r2m := &signRound2msg{
			C1:         s.c1jis[j].Bytes(),
			ProofBob:   res.proofBob,
			C2:         s.c2jis[j].Bytes(),
			ProofBobWC: res.proofBobWC,
		}
		m := tss.JsonWrap("ecdsa:sign:round2", r2m, Pi, Pj)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 2 messages -> triggers round 3
	rcv := tss.NewJsonExpect[signRound2msg]("ecdsa:sign:round2", otherIds, s.round3)
	s.params.Broker().Connect("ecdsa:sign:round2", rcv)
}

func (s *Signing) round3(otherIds []*tss.PartyID, r2msgs []*signRound2msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()
	allParties := s.params.Parties().IDs()

	// Build index mapping
	partyIdxMap := make(map[int]int)
	for k, oid := range otherIds {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				partyIdxMap[k] = n
				break
			}
		}
	}

	alphas := make([]*big.Int, len(allParties))
	us := make([]*big.Int, len(allParties))

	errChs := make(chan error, len(otherIds)*2)
	wg := sync.WaitGroup{}
	wg.Add(len(otherIds) * 2)

	for k := range otherIds {
		j := partyIdxMap[k]
		ContextJ := common.AppendBigIntToBytesSlice(s.ssid, big.NewInt(int64(j)))

		// AliceEnd
		go func(k, j int, ContextJ []byte) {
			defer wg.Done()
			proofBob, err := mta.ProofBobFromBytes(r2msgs[k].ProofBob)
			if err != nil {
				errChs <- fmt.Errorf("party %d: ProofBobFromBytes failed: %w", j, err)
				return
			}
			alphaIj, err := mta.AliceEnd(
				ContextJ,
				ec,
				s.key.PaillierPKs[i],
				proofBob,
				s.key.H1j[i],
				s.key.H2j[i],
				s.cis[j],
				new(big.Int).SetBytes(r2msgs[k].C1),
				s.key.NTildej[i],
				s.key.PaillierSK,
			)
			if err != nil {
				errChs <- fmt.Errorf("party %d: AliceEnd failed: %w", j, err)
				return
			}
			alphas[j] = alphaIj
		}(k, j, ContextJ)

		// AliceEndWC
		go func(k, j int, ContextJ []byte) {
			defer wg.Done()
			proofBobWC, err := mta.ProofBobWCFromBytes(ec, r2msgs[k].ProofBobWC)
			if err != nil {
				errChs <- fmt.Errorf("party %d: ProofBobWCFromBytes failed: %w", j, err)
				return
			}
			uIj, err := mta.AliceEndWC(
				ContextJ,
				ec,
				s.key.PaillierPKs[i],
				proofBobWC,
				s.bigWs[j],
				s.cis[j],
				new(big.Int).SetBytes(r2msgs[k].C2),
				s.key.NTildej[i],
				s.key.H1j[i],
				s.key.H2j[i],
				s.key.PaillierSK,
			)
			if err != nil {
				errChs <- fmt.Errorf("party %d: AliceEndWC failed: %w", j, err)
				return
			}
			us[j] = uIj
		}(k, j, ContextJ)
	}

	wg.Wait()
	close(errChs)
	for err := range errChs {
		if err != nil {
			s.Err <- err
			return
		}
	}

	// Compute theta and sigma
	modN := common.ModInt(ec.Params().N)
	theta := modN.Mul(s.k, s.gamma)
	sigma := modN.Mul(s.k, s.w)

	for k := range otherIds {
		j := partyIdxMap[k]
		alphaPlusBeta := modN.Add(alphas[j], s.betas[j])
		theta = modN.Add(theta, alphaPlusBeta)
		uPlusV := modN.Add(us[j], s.vs[j])
		sigma = modN.Add(sigma, uPlusV)
	}

	s.theta = theta
	s.sigma = sigma

	// Broadcast theta
	r3msg := &signRound3msg{
		Theta: theta.Bytes(),
	}
	var nextOtherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		nextOtherIds = append(nextOtherIds, p)
		m := tss.JsonWrap("ecdsa:sign:round3", r3msg, Pi, p)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 3 messages -> triggers round 4
	rcv := tss.NewJsonExpect[signRound3msg]("ecdsa:sign:round3", nextOtherIds, s.round4)
	s.params.Broker().Connect("ecdsa:sign:round3", rcv)
}

func (s *Signing) round4(otherIds []*tss.PartyID, r3msgs []*signRound3msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()
	allParties := s.params.Parties().IDs()

	modN := common.ModInt(ec.Params().N)

	// Sum all thetas
	thetaTotal := new(big.Int).Set(s.theta)
	for _, r3msg := range r3msgs {
		thetaJ := new(big.Int).SetBytes(r3msg.Theta)
		thetaTotal = modN.Add(thetaTotal, thetaJ)
	}

	// Compute multiplicative inverse of theta mod q
	thetaInverse := modN.ModInverse(thetaTotal)
	s.thetaInverse = thetaInverse

	// Schnorr proof for gamma
	ContextI := append(s.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)
	piGamma, err := schnorr.NewZKProof(ContextI, s.gamma, s.pointGamma, s.params.Rand())
	if err != nil {
		s.Err <- fmt.Errorf("NewZKProof(gamma, pointGamma): %w", err)
		return
	}

	// Broadcast decommitment + proof
	dcBzs := common.BigIntsToBytes(s.deCommit)
	r4msg := &signRound4msg{
		DeCommitment: dcBzs,
		ProofAlphaX:  piGamma.Alpha.X().Bytes(),
		ProofAlphaY:  piGamma.Alpha.Y().Bytes(),
		ProofT:       piGamma.T.Bytes(),
	}

	var nextOtherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		nextOtherIds = append(nextOtherIds, p)
		m := tss.JsonWrap("ecdsa:sign:round4", r4msg, Pi, p)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 4 messages -> triggers round 5
	rcv := tss.NewJsonExpect[signRound4msg]("ecdsa:sign:round4", nextOtherIds, s.round5)
	s.params.Broker().Connect("ecdsa:sign:round4", rcv)
}

func (s *Signing) round5(otherIds []*tss.PartyID, r4msgs []*signRound4msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()
	allParties := s.params.Parties().IDs()

	// Build index mapping
	partyIdxMap := make(map[int]int)
	for k, oid := range otherIds {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				partyIdxMap[k] = n
				break
			}
		}
	}

	// Start with our own pointGamma
	R := s.pointGamma

	// For each other party: verify decommitment and Schnorr proof, accumulate pointGamma
	for k := range otherIds {
		j := partyIdxMap[k]
		ContextJ := common.AppendBigIntToBytesSlice(s.ssid, big.NewInt(int64(j)))

		// Verify decommitment: commitment from round 1 msg2, decommitment from round 4
		SCj := s.r1Commitments[j]
		SDj := cmts.NewHashDeCommitmentFromBytes(r4msgs[k].DeCommitment)
		cmtDeCmt := cmts.HashCommitDecommit{C: SCj, D: SDj}
		ok, bigGammaJ := cmtDeCmt.DeCommit()
		if !ok || len(bigGammaJ) != 2 {
			s.Err <- fmt.Errorf("party %d: commitment verification failed", j)
			return
		}

		bigGammaJPoint, err := crypto.NewECPoint(ec, bigGammaJ[0], bigGammaJ[1])
		if err != nil {
			s.Err <- fmt.Errorf("party %d: NewECPoint(bigGammaJ): %w", j, err)
			return
		}

		// Verify Schnorr proof
		alphaX := new(big.Int).SetBytes(r4msgs[k].ProofAlphaX)
		alphaY := new(big.Int).SetBytes(r4msgs[k].ProofAlphaY)
		alpha, err := crypto.NewECPoint(ec, alphaX, alphaY)
		if err != nil {
			s.Err <- fmt.Errorf("party %d: failed to reconstruct Schnorr proof alpha point: %w", j, err)
			return
		}
		proof := &schnorr.ZKProof{
			Alpha: alpha,
			T:     new(big.Int).SetBytes(r4msgs[k].ProofT),
		}
		if !proof.Verify(ContextJ, bigGammaJPoint) {
			s.Err <- fmt.Errorf("party %d: Schnorr proof verification failed for bigGamma", j)
			return
		}

		R, err = R.Add(bigGammaJPoint)
		if err != nil {
			s.Err <- fmt.Errorf("party %d: R.Add(bigGammaJ): %w", j, err)
			return
		}
	}

	// R = bigGamma * thetaInverse
	R = R.ScalarMult(s.thetaInverse)

	N := ec.Params().N
	modN := common.ModInt(N)
	rx := R.X()
	ry := R.Y()
	si := modN.Add(modN.Mul(s.m, s.k), modN.Mul(rx, s.sigma))

	// Clear secret values
	s.w = zero
	s.k = zero
	s.gamma = zero

	// Generate random li, roi
	li := common.GetRandomPositiveInt(s.params.Rand(), N)
	roI := common.GetRandomPositiveInt(s.params.Rand(), N)

	// Compute bigVi = R^si + G^li
	rToSi := R.ScalarMult(si)
	liPoint := crypto.ScalarBaseMult(ec, li)
	bigAi := crypto.ScalarBaseMult(ec, roI)
	bigVi, err := rToSi.Add(liPoint)
	if err != nil {
		s.Err <- fmt.Errorf("rToSi.Add(liPoint): %w", err)
		return
	}

	// Commit to (bigVi.X, bigVi.Y, bigAi.X, bigAi.Y)
	cmt := cmts.NewHashCommitment(s.params.Rand(), bigVi.X(), bigVi.Y(), bigAi.X(), bigAi.Y())

	s.li = li
	s.roi = roI
	s.bigAi = bigAi
	s.bigVi = bigVi
	s.si = si
	s.rx = rx
	s.ry = ry
	s.bigR = R
	s.r5DeCommit = cmt.D

	// Broadcast commitment
	r5msg := &signRound5msg{
		Commitment: cmt.C.Bytes(),
	}

	var nextOtherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		nextOtherIds = append(nextOtherIds, p)
		m := tss.JsonWrap("ecdsa:sign:round5", r5msg, Pi, p)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 5 messages -> triggers round 6
	rcv := tss.NewJsonExpect[signRound5msg]("ecdsa:sign:round5", nextOtherIds, s.round6)
	s.params.Broker().Connect("ecdsa:sign:round5", rcv)
}

func (s *Signing) round6(otherIds []*tss.PartyID, r5msgs []*signRound5msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	allParties := s.params.Parties().IDs()

	// Store commitments from round 5
	for k, oid := range otherIds {
		for j, Pj := range allParties {
			if Pj.KeyInt().Cmp(oid.KeyInt()) == 0 {
				s.r5Commitments[j] = new(big.Int).SetBytes(r5msgs[k].Commitment)
				break
			}
		}
	}

	// Create Schnorr proofs
	ContextI := append(s.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)
	piAi, err := schnorr.NewZKProof(ContextI, s.roi, s.bigAi, s.params.Rand())
	if err != nil {
		s.Err <- fmt.Errorf("NewZKProof(roi, bigAi): %w", err)
		return
	}
	piV, err := schnorr.NewZKVProof(ContextI, s.bigVi, s.bigR, s.si, s.li, s.params.Rand())
	if err != nil {
		s.Err <- fmt.Errorf("NewZKVProof(bigVi, bigR, si, li): %w", err)
		return
	}

	// Broadcast decommitment + proofs
	dcBzs := common.BigIntsToBytes(s.r5DeCommit)
	r6msg := &signRound6msg{
		DeCommitment: dcBzs,
		ProofAlphaX:  piAi.Alpha.X().Bytes(),
		ProofAlphaY:  piAi.Alpha.Y().Bytes(),
		ProofT:       piAi.T.Bytes(),
		VProofAlphaX: piV.Alpha.X().Bytes(),
		VProofAlphaY: piV.Alpha.Y().Bytes(),
		VProofT:      piV.T.Bytes(),
		VProofU:      piV.U.Bytes(),
	}

	var nextOtherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		nextOtherIds = append(nextOtherIds, p)
		m := tss.JsonWrap("ecdsa:sign:round6", r6msg, Pi, p)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 6 messages -> triggers round 7
	rcv := tss.NewJsonExpect[signRound6msg]("ecdsa:sign:round6", nextOtherIds, s.round7)
	s.params.Broker().Connect("ecdsa:sign:round6", rcv)
}

func (s *Signing) round7(otherIds []*tss.PartyID, r6msgs []*signRound6msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()
	allParties := s.params.Parties().IDs()

	// Build index mapping
	partyIdxMap := make(map[int]int)
	for k, oid := range otherIds {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				partyIdxMap[k] = n
				break
			}
		}
	}

	bigVjs := make([]*crypto.ECPoint, len(allParties))
	bigAjs := make([]*crypto.ECPoint, len(allParties))

	for k := range otherIds {
		j := partyIdxMap[k]
		ContextJ := common.AppendBigIntToBytesSlice(s.ssid, big.NewInt(int64(j)))

		// Verify decommitment: commitment from round 5, decommitment from round 6
		cj := s.r5Commitments[j]
		dj := cmts.NewHashDeCommitmentFromBytes(r6msgs[k].DeCommitment)
		cmtDeCmt := cmts.HashCommitDecommit{C: cj, D: dj}
		ok, values := cmtDeCmt.DeCommit()
		if !ok || len(values) != 4 {
			s.Err <- fmt.Errorf("party %d: de-commitment for bigVj and bigAj failed", j)
			return
		}

		bigVjX, bigVjY, bigAjX, bigAjY := values[0], values[1], values[2], values[3]
		bigVj, err := crypto.NewECPoint(ec, bigVjX, bigVjY)
		if err != nil {
			s.Err <- fmt.Errorf("party %d: NewECPoint(bigVj): %w", j, err)
			return
		}
		bigVjs[j] = bigVj

		bigAj, err := crypto.NewECPoint(ec, bigAjX, bigAjY)
		if err != nil {
			s.Err <- fmt.Errorf("party %d: NewECPoint(bigAj): %w", j, err)
			return
		}
		bigAjs[j] = bigAj

		// Verify Schnorr proof for Aj
		pAlphaX := new(big.Int).SetBytes(r6msgs[k].ProofAlphaX)
		pAlphaY := new(big.Int).SetBytes(r6msgs[k].ProofAlphaY)
		pAlpha, err := crypto.NewECPoint(ec, pAlphaX, pAlphaY)
		if err != nil {
			s.Err <- fmt.Errorf("party %d: failed to reconstruct Schnorr proof alpha for Aj: %w", j, err)
			return
		}
		pijA := &schnorr.ZKProof{
			Alpha: pAlpha,
			T:     new(big.Int).SetBytes(r6msgs[k].ProofT),
		}
		if !pijA.Verify(ContextJ, bigAj) {
			s.Err <- fmt.Errorf("party %d: Schnorr verify for Aj failed", j)
			return
		}

		// Verify ZKV proof for Vj
		vAlphaX := new(big.Int).SetBytes(r6msgs[k].VProofAlphaX)
		vAlphaY := new(big.Int).SetBytes(r6msgs[k].VProofAlphaY)
		vAlpha, err := crypto.NewECPoint(ec, vAlphaX, vAlphaY)
		if err != nil {
			s.Err <- fmt.Errorf("party %d: failed to reconstruct ZKV proof alpha for Vj: %w", j, err)
			return
		}
		pijV := &schnorr.ZKVProof{
			Alpha: vAlpha,
			T:     new(big.Int).SetBytes(r6msgs[k].VProofT),
			U:     new(big.Int).SetBytes(r6msgs[k].VProofU),
		}
		if !pijV.Verify(ContextJ, bigVj, s.bigR) {
			s.Err <- fmt.Errorf("party %d: ZKV proof verify for Vj failed", j)
			return
		}
	}

	// Compute aggregates
	modN := common.ModInt(ec.Params().N)
	AX, AY := s.bigAi.X(), s.bigAi.Y()

	// g^(-m) and y^(-r)
	minusM := modN.Sub(big.NewInt(0), s.m)
	gToMInvX, gToMInvY := ec.ScalarBaseMult(minusM.Bytes())
	minusR := modN.Sub(big.NewInt(0), s.rx)
	yToRInvX, yToRInvY := ec.ScalarMult(s.key.ECDSAPub.X(), s.key.ECDSAPub.Y(), minusR.Bytes())

	VX, VY := ec.Add(gToMInvX, gToMInvY, yToRInvX, yToRInvY)
	VX, VY = ec.Add(VX, VY, s.bigVi.X(), s.bigVi.Y())

	for k := range otherIds {
		j := partyIdxMap[k]
		VX, VY = ec.Add(VX, VY, bigVjs[j].X(), bigVjs[j].Y())
		AX, AY = ec.Add(AX, AY, bigAjs[j].X(), bigAjs[j].Y())
	}

	// Ui = V^roi, Ti = A^li
	UiX, UiY := ec.ScalarMult(VX, VY, s.roi.Bytes())
	TiX, TiY := ec.ScalarMult(AX, AY, s.li.Bytes())
	s.Ui = crypto.NewECPointNoCurveCheck(ec, UiX, UiY)
	s.Ti = crypto.NewECPointNoCurveCheck(ec, TiX, TiY)

	// Commit to (Ui.X, Ui.Y, Ti.X, Ti.Y)
	cmt := cmts.NewHashCommitment(s.params.Rand(), UiX, UiY, TiX, TiY)
	s.r7DeCommit = cmt.D

	// Broadcast commitment
	r7msg := &signRound7msg{
		Commitment: cmt.C.Bytes(),
	}

	var nextOtherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		nextOtherIds = append(nextOtherIds, p)
		m := tss.JsonWrap("ecdsa:sign:round7", r7msg, Pi, p)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 7 messages -> triggers round 8
	rcv := tss.NewJsonExpect[signRound7msg]("ecdsa:sign:round7", nextOtherIds, s.round8)
	s.params.Broker().Connect("ecdsa:sign:round7", rcv)
}

func (s *Signing) round8(otherIds []*tss.PartyID, r7msgs []*signRound7msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	allParties := s.params.Parties().IDs()

	// Store commitments from round 7
	for k, oid := range otherIds {
		for j, Pj := range allParties {
			if Pj.KeyInt().Cmp(oid.KeyInt()) == 0 {
				s.r7Commitments[j] = new(big.Int).SetBytes(r7msgs[k].Commitment)
				break
			}
		}
	}

	// Broadcast decommitment
	dcBzs := common.BigIntsToBytes(s.r7DeCommit)
	r8msg := &signRound8msg{
		DeCommitment: dcBzs,
	}

	var nextOtherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		nextOtherIds = append(nextOtherIds, p)
		m := tss.JsonWrap("ecdsa:sign:round8", r8msg, Pi, p)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 8 messages -> triggers round 9
	rcv := tss.NewJsonExpect[signRound8msg]("ecdsa:sign:round8", nextOtherIds, s.round9)
	s.params.Broker().Connect("ecdsa:sign:round8", rcv)
}

func (s *Signing) round9(otherIds []*tss.PartyID, r8msgs []*signRound8msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()
	allParties := s.params.Parties().IDs()

	// Build index mapping
	partyIdxMap := make(map[int]int)
	for k, oid := range otherIds {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				partyIdxMap[k] = n
				break
			}
		}
	}

	// Verify decommitments and sum U and T
	UX, UY := s.Ui.X(), s.Ui.Y()
	TX, TY := s.Ti.X(), s.Ti.Y()

	for k := range otherIds {
		j := partyIdxMap[k]

		cj := s.r7Commitments[j]
		dj := cmts.NewHashDeCommitmentFromBytes(r8msgs[k].DeCommitment)
		cmtObj := cmts.HashCommitDecommit{C: cj, D: dj}
		ok, values := cmtObj.DeCommit()
		if !ok || len(values) != 4 {
			s.Err <- fmt.Errorf("party %d: de-commitment for Uj and Tj failed", j)
			return
		}
		UjX, UjY, TjX, TjY := values[0], values[1], values[2], values[3]
		UX, UY = ec.Add(UX, UY, UjX, UjY)
		TX, TY = ec.Add(TX, TY, TjX, TjY)
	}

	// Check U == T
	if UX.Cmp(TX) != 0 || UY.Cmp(TY) != 0 {
		s.Err <- errors.New("U doesn't equal T")
		return
	}

	// Broadcast si
	r9msg := &signRound9msg{
		Si: s.si.Bytes(),
	}

	var nextOtherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		nextOtherIds = append(nextOtherIds, p)
		m := tss.JsonWrap("ecdsa:sign:round9", r9msg, Pi, p)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 9 messages -> triggers finalize
	rcv := tss.NewJsonExpect[signRound9msg]("ecdsa:sign:round9", nextOtherIds, s.finalize)
	s.params.Broker().Connect("ecdsa:sign:round9", rcv)
}

func (s *Signing) finalize(otherIds []*tss.PartyID, r9msgs []*signRound9msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	ec := s.params.EC()
	modN := common.ModInt(ec.Params().N)

	// Sum all si values
	sumS := new(big.Int).Set(s.si)
	for _, r9msg := range r9msgs {
		sj := new(big.Int).SetBytes(r9msg.Si)
		sumS = modN.Add(sumS, sj)
	}

	// Compute recovery byte
	recid := 0
	if s.rx.Cmp(ec.Params().N) > 0 {
		recid = 2
	}
	if s.ry.Bit(0) != 0 {
		recid |= 1
	}

	// Low-S normalization (BIP-62)
	halfN := new(big.Int).Rsh(ec.Params().N, 1)
	if sumS.Cmp(halfN) > 0 {
		sumS.Sub(ec.Params().N, sumS)
		recid ^= 1
	}

	// Build signature data
	bitSizeInBytes := ec.Params().BitSize / 8
	rBytes := padToLengthBytesInPlace(s.rx.Bytes(), bitSizeInBytes)
	sBytes := padToLengthBytesInPlace(sumS.Bytes(), bitSizeInBytes)

	sigData := &SignatureData{
		R:         rBytes,
		S:         sBytes,
		Signature: append(rBytes, sBytes...),
		Recovery:  byte(recid),
		M:         s.m.Bytes(),
	}

	// Verify signature
	pk := ecdsa.PublicKey{
		Curve: ec,
		X:     s.key.ECDSAPub.X(),
		Y:     s.key.ECDSAPub.Y(),
	}

	ok := ecdsa.Verify(&pk, sigData.M, s.rx, sumS)
	if !ok {
		s.Err <- fmt.Errorf("signature verification failed")
		return
	}

	s.Done <- sigData
}

func padToLengthBytesInPlace(src []byte, length int) []byte {
	if len(src) >= length {
		return src
	}
	padded := make([]byte, length)
	copy(padded[length-len(src):], src)
	return padded
}
