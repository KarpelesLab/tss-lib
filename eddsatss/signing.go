package eddsatss

import (
	"context"
	"sync"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	cmts "github.com/KarpelesLab/tss-lib/v2/crypto/commitments"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Signing tracks a threshold EdDSA signing operation.
type Signing struct {
	ctx       context.Context
	params    *tss.Parameters
	key       *Key
	msg       *big.Int
	wi        *big.Int
	ri        *big.Int
	pointRi   *crypto.ECPoint
	deCommit  cmts.HashDeCommitment
	cjs       []*big.Int
	ssid      []byte
	ssidNonce *big.Int

	Done chan *SignatureData
	Err  chan error

	// Once-guards on Done/Err so multi-writer error paths cannot block on
	// the size-1 buffer. See once_send.go for the rationale.
	doneOnce sync.Once
	errOnce  sync.Once
}

// NewSigning creates a new Signing instance and kicks off round 1 of the EdDSA signing protocol.
//
// The receiver key may have been produced by a keygen that involved more parties than the
// current signing committee; NewSigning transparently reindexes Ks and BigXj to match
// params.Parties().IDs() via SubsetForParties, so callers can pass the full keygen key as-is.
func (key *Key) NewSigning(ctx context.Context, msg *big.Int, params *tss.Parameters) (*Signing, error) {
	subsetKey, err := key.SubsetForParties(params.Parties().IDs())
	if err != nil {
		return nil, err
	}
	partyCount := params.PartyCount()
	s := &Signing{
		ctx:    ctx,
		params: params,
		key:    subsetKey,
		msg:    msg,
		cjs:    make([]*big.Int, partyCount),
		Done:   make(chan *SignatureData, 1),
		Err:    make(chan error, 1),
	}
	if err := s.round1(); err != nil {
		return nil, err
	}
	return s, nil
}

// getSSID returns ssid from local params, including BigXj in the hash (unlike keygen).
func (s *Signing) getSSID(roundNum int) ([]byte, error) {
	ssidList := []*big.Int{
		s.params.EC().Params().P,
		s.params.EC().Params().N,
		s.params.EC().Params().Gx,
		s.params.EC().Params().Gy,
	}
	ssidList = append(ssidList, s.params.Parties().IDs().Keys()...)
	BigXjList, err := crypto.FlattenECPoints(s.key.BigXj)
	if err != nil {
		return nil, fmt.Errorf("read BigXj failed: %w", err)
	}
	ssidList = append(ssidList, BigXjList...)
	ssidList = append(ssidList, big.NewInt(int64(roundNum)))
	ssidList = append(ssidList, s.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()
	return ssid, nil
}

func (s *Signing) round1() error {
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()

	// prepare wi (Lagrange coefficient)
	xi := s.key.Xi
	ks := s.key.Ks
	if s.params.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", s.params.Threshold()+1, len(ks))
	}
	s.wi = PrepareForSigning(ec, i, len(ks), xi, ks)

	// select random ri
	ri := common.GetRandomPositiveInt(s.params.Rand(), ec.Params().N)
	s.ri = ri

	// compute Ri = ri * G via the CT scalar-mult primitive (edwards25519
	// fixed-base table). `ri` is the per-party EdDSA signing nonce —
	// leaking its bits via timing is a textbook hidden-number / nonce-bias
	// attack on EdDSA and recovers the share scalar `wi`. The standard
	// crypto.ScalarBaseMult routes through Go's elliptic curve impl which
	// is documented as not constant-time for these curves.
	pointRi := crypto.CTScalarBaseMultEd25519(ec, ri)
	s.pointRi = pointRi

	// make commitment to pointRi
	cmt := cmts.NewHashCommitment(s.params.Rand(), pointRi.X(), pointRi.Y())
	s.deCommit = cmt.D

	// compute ssid. ssidNonce is hard-coded to 0 because every party
	// computes ssid independently and must produce the same value (the
	// Schnorr PoK at round 2 uses ssid as Fiat-Shamir context — see
	// the matching note in keygen.go for why a per-party random nonce
	// breaks verification). Per-session uniqueness would require a
	// coin-flipping round, which is a protocol redesign.
	s.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	s.ssid, err = s.getSSID(1)
	if err != nil {
		return fmt.Errorf("failed to generate ssid: %w", err)
	}

	// build list of other party IDs
	var otherIds []*tss.PartyID
	for n, p := range s.params.Parties().IDs() {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	// Broadcast round 1 commitment via a single To==nil message. The
	// hash commitment to point R_i has identical bytes for every
	// recipient; sending it as a true broadcast lets a well-behaved
	// broker enforce "same bytes to every recipient" rather than
	// allowing a malicious sender to equivocate by shipping different
	// commitments under N-1 unicasts. Round-2 decommit + Schnorr PoK
	// then enforces correctness regardless.
	msg := &signRound1msg{
		Commitment: cmt.C.Bytes(),
	}
	m := tss.JsonWrap("eddsa:sign:round1", msg, Pi, nil)
	s.params.Broker().Receive(m)

	// register receiver for round 1 messages from others -> triggers round 2
	rcv := tss.NewJsonExpect[signRound1msg]("eddsa:sign:round1", otherIds, s.round2)
	s.params.Broker().Connect("eddsa:sign:round1", rcv)

	return nil
}

func (s *Signing) round2(otherIds []*tss.PartyID, r1msgs []*signRound1msg) {
	if s.ctx.Err() != nil {
		sendOnce(&s.errOnce, s.Err, s.ctx.Err())
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index

	// store commitments from round 1
	for n, pid := range otherIds {
		for j, Pj := range s.params.Parties().IDs() {
			if Pj.KeyInt().Cmp(pid.KeyInt()) == 0 {
				s.cjs[j] = new(big.Int).SetBytes(r1msgs[n].Commitment)
				break
			}
		}
	}

	// compute Schnorr proof for ri
	ContextI := append(s.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)
	pir, err := schnorr.NewZKProof(ContextI, s.ri, s.pointRi, s.params.Rand())
	if err != nil {
		sendOnce(&s.errOnce, s.Err, fmt.Errorf("NewZKProof(ri, pointRi): %w", err))
		return
	}

	// Broadcast decommitment + Schnorr proof via a single To==nil message
	// (identical bytes per recipient — see round1 for the rationale).
	r2msg := &signRound2msg{
		DeCommitment:       common.BigIntsToBytes(s.deCommit),
		SchnorrProofAlphaX: pir.Alpha.X().Bytes(),
		SchnorrProofAlphaY: pir.Alpha.Y().Bytes(),
		SchnorrProofT:      pir.T.Bytes(),
	}
	m := tss.JsonWrap("eddsa:sign:round2", r2msg, Pi, nil)
	s.params.Broker().Receive(m)

	// register receiver for round 2 messages from others -> triggers round 3
	rcv := tss.NewJsonExpect[signRound2msg]("eddsa:sign:round2", otherIds, s.round3)
	s.params.Broker().Connect("eddsa:sign:round2", rcv)
}

func (s *Signing) round3(otherIds []*tss.PartyID, r2msgs []*signRound2msg) {
	if s.ctx.Err() != nil {
		sendOnce(&s.errOnce, s.Err, s.ctx.Err())
		return
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()

	// init R from our own ri
	var R edwards25519.ExtendedGroupElement
	riBytes := bigIntToEncodedBytes(s.ri)
	edwards25519.GeScalarMultBase(&R, riBytes)

	// verify each other party's decommitment and Schnorr proof, compute R
	for n, pid := range otherIds {
		// find the index j for this party
		j := -1
		for idx, Pj := range s.params.Parties().IDs() {
			if Pj.KeyInt().Cmp(pid.KeyInt()) == 0 {
				j = idx
				break
			}
		}
		if j == -1 {
			sendOnce(&s.errOnce, s.Err, errors.New("party not found"))
			return
		}

		ContextJ := common.AppendBigIntToBytesSlice(s.ssid, big.NewInt(int64(j)))

		// verify decommitment
		KGDj := cmts.NewHashDeCommitmentFromBytes(r2msgs[n].DeCommitment)
		cmtDeCmt := cmts.HashCommitDecommit{C: s.cjs[j], D: KGDj}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			sendOnce(&s.errOnce, s.Err, errors.New("de-commitment verify failed"))
			return
		}
		if len(coordinates) != 2 {
			sendOnce(&s.errOnce, s.Err, errors.New("length of de-commitment should be 2"))
			return
		}

		Rj, err := crypto.NewECPoint(ec, coordinates[0], coordinates[1])
		if err != nil {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("NewECPoint(Rj): %w", err))
			return
		}
		Rj = Rj.EightInvEight()

		// verify Schnorr proof
		alphaX := new(big.Int).SetBytes(r2msgs[n].SchnorrProofAlphaX)
		alphaY := new(big.Int).SetBytes(r2msgs[n].SchnorrProofAlphaY)
		alpha, err := crypto.NewECPoint(ec, alphaX, alphaY)
		if err != nil {
			sendOnce(&s.errOnce, s.Err, errors.New("failed to reconstruct Schnorr proof alpha point"))
			return
		}
		proof := &schnorr.ZKProof{
			Alpha: alpha,
			T:     new(big.Int).SetBytes(r2msgs[n].SchnorrProofT),
		}
		if !proof.Verify(ContextJ, Rj) {
			sendOnce(&s.errOnce, s.Err, errors.New("Schnorr proof verification failed for Rj"))
			return
		}

		// add to running total R
		extendedRj := ecPointToExtendedElement(ec, Rj.X(), Rj.Y(), s.params.Rand())
		R = addExtendedElements(R, extendedRj)
	}

	// encode R to bytes
	var encodedR [32]byte
	R.ToBytes(&encodedR)

	// encode public key
	encodedPubKey := ecPointToEncodedBytes(s.key.EDDSAPub.X(), s.key.EDDSAPub.Y())

	// compute lambda: SHA-512(encodedR || encodedPubKey || encodedMsg)
	h := sha512.New()
	h.Write(encodedR[:])
	h.Write(encodedPubKey[:])
	h.Write(s.msg.Bytes())

	var lambda [64]byte
	h.Sum(lambda[:0])
	var lambdaReduced [32]byte
	edwards25519.ScReduce(&lambdaReduced, &lambda)

	// compute si = lambdaReduced * wi + ri
	var localS [32]byte
	edwards25519.ScMulAdd(&localS, &lambdaReduced, bigIntToEncodedBytes(s.wi), riBytes)

	// store R for finalization
	r := encodedBytesToBigInt(&encodedR)

	// Broadcast si via a single To==nil message (identical per recipient).
	r3msg := &signRound3msg{
		Si: localS[:],
	}
	m := tss.JsonWrap("eddsa:sign:round3", r3msg, Pi, nil)
	s.params.Broker().Receive(m)

	// register receiver for round 3 messages from others -> triggers finalize
	rcv := tss.NewJsonExpect[signRound3msg]("eddsa:sign:round3", otherIds, func(ids []*tss.PartyID, msgs []*signRound3msg) {
		s.finalize(r, &localS, &encodedR, msgs)
	})
	s.params.Broker().Connect("eddsa:sign:round3", rcv)

	// suppress unused variable warning
	_ = i
}

func (s *Signing) finalize(r *big.Int, localS *[32]byte, encodedR *[32]byte, r3msgs []*signRound3msg) {
	if s.ctx.Err() != nil {
		sendOnce(&s.errOnce, s.Err, s.ctx.Err())
		return
	}
	// sum all sj: start with our own si
	sumS := *localS
	one := [32]byte{}
	one[0] = 1 // little-endian 1

	for _, msg := range r3msgs {
		sjBytes := copyBytes(msg.Si)
		var tmpSumS [32]byte
		edwards25519.ScMulAdd(&tmpSumS, &sumS, &one, sjBytes)
		sumS = tmpSumS
	}

	sInt := encodedBytesToBigInt(&sumS)

	// build signature data
	sigData := &SignatureData{
		Signature: append(encodedR[:], sumS[:]...),
		R:         r.Bytes(),
		S:         sInt.Bytes(),
		M:         s.msg.Bytes(),
	}

	// verify signature
	pk := edwards25519.PublicKey{
		Curve: s.params.EC(),
		X:     s.key.EDDSAPub.X(),
		Y:     s.key.EDDSAPub.Y(),
	}

	ok := edwards25519.VerifyRS(&pk, sigData.M, r, sInt)
	if !ok {
		sendOnce(&s.errOnce, s.Err, fmt.Errorf("signature verification failed"))
		return
	}

	sendOnce(&s.doneOnce, s.Done, sigData)
}
