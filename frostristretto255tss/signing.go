package frostristretto255tss

import (
	"context"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Signing tracks a threshold FROST(ristretto255) signing operation per
// RFC 9591 §5 (two-round non-coordinator).
type Signing struct {
	ctx    context.Context
	params *tss.Parameters
	key    *Key
	msg    []byte

	di, ei *big.Int
	Di, Ei group.Element

	Done chan *SignatureData
	Err  chan error
}

// NewSigning starts a FROST(ristretto255) signing session.
//
// The key may have been produced by a keygen with more parties than the
// current signing committee; the receiver-side Ks/BigXj are transparently
// reindexed via SubsetForParties.
func (key *Key) NewSigning(ctx context.Context, msg []byte, params *tss.Parameters) (*Signing, error) {
	if params.PartyCount() < params.Threshold()+1 {
		return nil, fmt.Errorf("frostristretto255tss: signing committee size %d < threshold+1 (%d)",
			params.PartyCount(), params.Threshold()+1)
	}
	subset, err := key.SubsetForParties(params.Parties().IDs())
	if err != nil {
		return nil, err
	}
	s := &Signing{
		ctx:    ctx,
		params: params,
		key:    subset,
		msg:    msg,
		Done:   make(chan *SignatureData, 1),
		Err:    make(chan error, 1),
	}
	if err := s.round1(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Signing) round1() error {
	Pi := s.params.PartyID()
	i := Pi.Index
	g := group.Ristretto255()

	s.di = g.RandomScalar(s.params.Rand())
	s.ei = g.RandomScalar(s.params.Rand())
	s.Di = g.ScalarBaseMult(s.di)
	s.Ei = g.ScalarBaseMult(s.ei)

	var otherIds []*tss.PartyID
	for n, p := range s.params.Parties().IDs() {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	r1 := &signRound1msg{
		Hiding:  s.Di.Bytes(),
		Binding: s.Ei.Bytes(),
	}
	for _, p := range otherIds {
		m := tss.JsonWrap("frost:ristretto255:sign:round1", r1, Pi, p)
		s.params.Broker().Receive(m)
	}

	rcv := tss.NewJsonExpect[signRound1msg]("frost:ristretto255:sign:round1", otherIds, s.round2)
	s.params.Broker().Connect("frost:ristretto255:sign:round1", rcv)
	return nil
}

func (s *Signing) round2(otherIds []*tss.PartyID, r1msgs []*signRound1msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	g := group.Ristretto255()
	cs := frost.Ristretto255Ciphersuite()

	commitments := make([]frost.NonceCommitment, 0, len(otherIds)+1)
	commitments = append(commitments, frost.NonceCommitment{
		Identifier: Pi.KeyInt(),
		Hiding:     s.Di,
		Binding:    s.Ei,
	})
	for n, pid := range otherIds {
		Dj, err := g.DecodeElement(r1msgs[n].Hiding)
		if err != nil {
			s.Err <- fmt.Errorf("party %s sent invalid hiding commitment: %w", pid, err)
			return
		}
		Ej, err := g.DecodeElement(r1msgs[n].Binding)
		if err != nil {
			s.Err <- fmt.Errorf("party %s sent invalid binding commitment: %w", pid, err)
			return
		}
		commitments = append(commitments, frost.NonceCommitment{
			Identifier: pid.KeyInt(),
			Hiding:     Dj,
			Binding:    Ej,
		})
	}

	bindingFactors := frost.ComputeBindingFactors(cs, s.msg, commitments)
	R, err := frost.ComputeGroupCommitment(commitments, bindingFactors)
	if err != nil {
		s.Err <- fmt.Errorf("ComputeGroupCommitment: %w", err)
		return
	}
	c := frost.ComputeGroupChallenge(cs, R, s.key.GroupPublicKey, s.msg)

	signerIDs := make([]*big.Int, 0, len(commitments))
	for _, cm := range commitments {
		signerIDs = append(signerIDs, cm.Identifier)
	}
	lambda_i := frost.LagrangeCoefficient(cs, Pi.KeyInt(), signerIDs)

	rho_i := bindingFactors[Pi.KeyInt().String()]
	modQ := common.ModInt(g.Order())
	term2 := modQ.Mul(s.ei, rho_i)
	term3 := modQ.Mul(modQ.Mul(lambda_i, s.key.Xi), c)
	zi := modQ.Add(modQ.Add(s.di, term2), term3)

	r2 := &signRound2msg{Z: g.EncodeScalar(zi)}
	for _, p := range otherIds {
		m := tss.JsonWrap("frost:ristretto255:sign:round2", r2, Pi, p)
		s.params.Broker().Receive(m)
	}

	rcv := tss.NewJsonExpect[signRound2msg]("frost:ristretto255:sign:round2", otherIds, func(ids []*tss.PartyID, msgs []*signRound2msg) {
		s.finalize(commitments, bindingFactors, R, c, zi, ids, msgs)
	})
	s.params.Broker().Connect("frost:ristretto255:sign:round2", rcv)
}

func (s *Signing) finalize(
	commitments []frost.NonceCommitment,
	bindingFactors map[string]*big.Int,
	R group.Element,
	c *big.Int,
	myZi *big.Int,
	r2Ids []*tss.PartyID,
	r2msgs []*signRound2msg,
) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	g := group.Ristretto255()
	cs := frost.Ristretto255Ciphersuite()
	modQ := common.ModInt(g.Order())

	bigXByID := make(map[string]group.Element, len(s.key.BigXj))
	for j, kj := range s.key.Ks {
		bigXByID[kj.String()] = s.key.BigXj[j]
	}
	commitByID := make(map[string]frost.NonceCommitment, len(commitments))
	for _, cm := range commitments {
		commitByID[cm.Identifier.String()] = cm
	}
	signerIDs := make([]*big.Int, 0, len(commitments))
	for _, cm := range commitments {
		signerIDs = append(signerIDs, cm.Identifier)
	}

	z := new(big.Int).Set(myZi)
	for n, pid := range r2Ids {
		zj, err := g.DecodeScalar(r2msgs[n].Z)
		if err != nil {
			s.Err <- fmt.Errorf("party %s sent invalid z: %w", pid, err)
			return
		}
		cm, ok := commitByID[pid.KeyInt().String()]
		if !ok {
			s.Err <- fmt.Errorf("missing nonce commitment for signer %s", pid)
			return
		}
		Yj, ok := bigXByID[pid.KeyInt().String()]
		if !ok {
			s.Err <- fmt.Errorf("missing verification share for signer %s", pid)
			return
		}
		rho_j := bindingFactors[cm.Identifier.String()]
		commitShare, err := cm.Hiding.Add(cm.Binding.ScalarMult(rho_j))
		if err != nil {
			s.Err <- fmt.Errorf("computing commitment_share for %s: %w", pid, err)
			return
		}
		lambda_j := frost.LagrangeCoefficient(cs, cm.Identifier, signerIDs)
		clambda := modQ.Mul(c, lambda_j)
		lhs := g.ScalarBaseMult(zj)
		rhs, err := commitShare.Add(Yj.ScalarMult(clambda))
		if err != nil {
			s.Err <- fmt.Errorf("computing verifier rhs for %s: %w", pid, err)
			return
		}
		if !lhs.Equal(rhs) {
			s.Err <- fmt.Errorf("partial signature from %s failed verification", pid)
			return
		}
		z = modQ.Add(z, zj)
	}

	rEnc := R.Bytes()
	sEnc := g.EncodeScalar(z)
	sig := make([]byte, 0, 64)
	sig = append(sig, rEnc...)
	sig = append(sig, sEnc...)

	// Self-verify via Schnorr-style check: z*G ?= R + c*pubkey.
	lhs := g.ScalarBaseMult(z)
	rhs, err := R.Add(s.key.GroupPublicKey.ScalarMult(c))
	if err != nil {
		s.Err <- fmt.Errorf("self-verify: %w", err)
		return
	}
	if !lhs.Equal(rhs) {
		s.Err <- fmt.Errorf("frostristretto255tss: aggregated signature failed local Schnorr check")
		return
	}

	s.Done <- &SignatureData{
		R:         rEnc,
		S:         sEnc,
		Signature: sig,
		M:         s.msg,
	}
}

// VerifySignature reproduces the FROST(ristretto255) verification equation:
//
//	z * G == R + c * pubKey, where c = H2(R || pubKey || msg)
//
// It is exposed so callers can verify externally-received signatures without
// needing to reconstruct the ciphersuite plumbing themselves.
func VerifySignature(pubKey group.Element, msg, signature []byte) (bool, error) {
	if len(signature) != 64 {
		return false, fmt.Errorf("frostristretto255tss: signature must be 64 bytes, got %d", len(signature))
	}
	g := group.Ristretto255()
	cs := frost.Ristretto255Ciphersuite()
	R, err := g.DecodeElement(signature[:32])
	if err != nil {
		return false, fmt.Errorf("decode R: %w", err)
	}
	z, err := g.DecodeScalar(signature[32:])
	if err != nil {
		return false, fmt.Errorf("decode S: %w", err)
	}
	c := frost.ComputeGroupChallenge(cs, R, pubKey, msg)
	lhs := g.ScalarBaseMult(z)
	rhs, err := R.Add(pubKey.ScalarMult(c))
	if err != nil {
		return false, err
	}
	return lhs.Equal(rhs), nil
}
