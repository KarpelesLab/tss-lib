package frosttss

import (
	"context"
	"sync"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Signing tracks a threshold FROST(Ed25519) signing operation. It implements
// the two-round non-coordinator signing protocol from RFC 9591 §5.
type Signing struct {
	ctx    context.Context
	params *tss.Parameters
	key    *Key
	msg    []byte

	// preprocessing nonces (round 1)
	di, ei *big.Int      // hiding and binding scalars
	Di, Ei group.Element // d_i*G, e_i*G

	Done chan *SignatureData
	Err  chan error

	// Once-guards on Done/Err so multi-writer error paths cannot block on
	// the size-1 buffer. See once_send.go for the rationale.
	doneOnce sync.Once
	errOnce  sync.Once
}

// NewSigning starts a FROST(Ed25519) signing session against the message msg.
//
// The receiver key may have been produced by a keygen that involved more
// parties than the current signing committee; NewSigning transparently
// reindexes Ks and BigXj to match params.Parties().IDs() via SubsetForParties.
//
// The signing committee size must be at least threshold+1.
func (key *Key) NewSigning(ctx context.Context, msg []byte, params *tss.Parameters) (*Signing, error) {
	if !tss.SameCurve(params.EC(), frost.EdwardsCurve()) {
		return nil, fmt.Errorf("frosttss: FROST(Ed25519) requires the Ed25519 curve")
	}
	if params.PartyCount() < params.Threshold()+1 {
		return nil, fmt.Errorf("frosttss: signing committee size %d < threshold+1 (%d)",
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

// round1 samples nonces (d_i, e_i), computes commitments (D_i, E_i), and
// broadcasts them.
func (s *Signing) round1() error {
	Pi := s.params.PartyID()
	i := Pi.Index
	g := group.Ed25519()

	s.di = g.RandomScalar(s.params.Rand())
	s.ei = g.RandomScalar(s.params.Rand())
	// D_i = d_i · G and E_i = e_i · G — the per-party FROST nonces.
	// Leaking d_i or e_i via timing is a hidden-number attack on the
	// joint signature and recovers the share scalar. group.Ed25519's
	// ScalarBaseMult uses crypto.ScalarBaseMult which is non-CT for
	// Ed25519; bypass via crypto.CTScalarBaseMultEd25519 (edwards25519
	// fixed-base table) and adapt the result back into the Group
	// abstraction.
	ec := frost.EdwardsCurve()
	s.Di = group.AdaptECPoint(crypto.CTScalarBaseMultEd25519(ec, s.di))
	s.Ei = group.AdaptECPoint(crypto.CTScalarBaseMultEd25519(ec, s.ei))

	var otherIds []*tss.PartyID
	for n, p := range s.params.Parties().IDs() {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	// Broadcast (D_i, E_i) via a single To==nil message. The pair is
	// identical for every recipient; sending as a true broadcast lets a
	// well-behaved broker enforce "same bytes to every recipient" and
	// prevents an equivocation channel where a malicious signer ships
	// different (D, E) pairs per recipient (downstream this would land
	// as a partial-signature verification failure rather than an
	// identifiable abort).
	r1 := &signRound1msg{
		Hiding:  s.Di.Bytes(),
		Binding: s.Ei.Bytes(),
	}
	m := tss.JsonWrap("frost:ed25519:sign:round1", r1, Pi, nil)
	s.params.Broker().Receive(m)

	rcv := tss.NewJsonExpect[signRound1msg]("frost:ed25519:sign:round1", otherIds, s.round2)
	s.params.Broker().Connect("frost:ed25519:sign:round1", rcv)
	return nil
}

// round2 assembles the full nonce-commitment list, derives binding factors,
// computes the group commitment R and challenge c, computes the partial
// signature z_i, and broadcasts it.
func (s *Signing) round2(otherIds []*tss.PartyID, r1msgs []*signRound1msg) {
	if s.ctx.Err() != nil {
		sendOnce(&s.errOnce, s.Err, s.ctx.Err())
		return
	}
	Pi := s.params.PartyID()
	g := group.Ed25519()
	cs := frost.Ed25519Ciphersuite()

	commitments := make([]frost.NonceCommitment, 0, len(otherIds)+1)
	commitments = append(commitments, frost.NonceCommitment{
		Identifier: Pi.KeyInt(),
		Hiding:     s.Di,
		Binding:    s.Ei,
	})
	for n, pid := range otherIds {
		Dj, err := g.DecodeElement(r1msgs[n].Hiding)
		if err != nil {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("party %s sent invalid hiding commitment: %w", pid, err))
			return
		}
		Ej, err := g.DecodeElement(r1msgs[n].Binding)
		if err != nil {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("party %s sent invalid binding commitment: %w", pid, err))
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
		sendOnce(&s.errOnce, s.Err, fmt.Errorf("ComputeGroupCommitment: %w", err))
		return
	}
	groupPubEl := group.AdaptECPoint(s.key.GroupPublicKey)
	c := frost.ComputeGroupChallenge(cs, R, groupPubEl, s.msg)

	signerIDs := make([]*big.Int, 0, len(commitments))
	for _, cm := range commitments {
		signerIDs = append(signerIDs, cm.Identifier)
	}
	lambda_i := frost.LagrangeCoefficient(cs, Pi.KeyInt(), signerIDs)

	// z_i = d_i + e_i · ρ_i + λ_i · s_i · c (mod L)
	//
	// Both nonces (d_i, e_i) and the share s_i are secret. Composing the
	// product `λ_i · s_i · c` through math/big.Int.Mul leaks bits of s_i;
	// composing `e_i · ρ_i` leaks bits of e_i. Re-express the expression
	// as a sequence of constant-time mul-add operations via
	// crypto.CTScalarMulAddModN (which routes through edwards25519.ScMulAdd
	// on Ed25519 — the same primitive RFC 8032 stdlib EdDSA uses):
	//
	//   t1 = e_i · ρ_i + d_i        (secret · public + secret)
	//   t2 = λ_i · s_i + 0          (public · secret)
	//   z_i = t2 · c + t1           (secret · public + secret)
	rho_i := bindingFactors[Pi.KeyInt().String()]
	ec := frost.EdwardsCurve()
	zero := new(big.Int)
	t1 := crypto.CTScalarMulAddModN(ec, s.ei, rho_i, s.di)
	t2 := crypto.CTScalarMulAddModN(ec, lambda_i, s.key.Xi, zero)
	zi := crypto.CTScalarMulAddModN(ec, t2, c, t1)

	// Broadcast z_i via a single To==nil message (identical per recipient).
	r2 := &signRound2msg{Z: g.EncodeScalar(zi)}
	m := tss.JsonWrap("frost:ed25519:sign:round2", r2, Pi, nil)
	s.params.Broker().Receive(m)

	rcv := tss.NewJsonExpect[signRound2msg]("frost:ed25519:sign:round2", otherIds, func(ids []*tss.PartyID, msgs []*signRound2msg) {
		s.finalize(commitments, bindingFactors, R, c, zi, ids, msgs)
	})
	s.params.Broker().Connect("frost:ed25519:sign:round2", rcv)
}

// finalize verifies each peer's partial signature, sums the partials, and
// emits the final (R, S) signature.
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
		sendOnce(&s.errOnce, s.Err, s.ctx.Err())
		return
	}
	g := group.Ed25519()
	cs := frost.Ed25519Ciphersuite()
	modQ := common.ModInt(g.Order())

	bigXByID := make(map[string]group.Element, len(s.key.BigXj))
	for j, kj := range s.key.Ks {
		bigXByID[kj.String()] = group.AdaptECPoint(s.key.BigXj[j])
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
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("party %s sent invalid z: %w", pid, err))
			return
		}
		cm, ok := commitByID[pid.KeyInt().String()]
		if !ok {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("missing nonce commitment for signer %s", pid))
			return
		}
		Yj, ok := bigXByID[pid.KeyInt().String()]
		if !ok {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("missing verification share for signer %s", pid))
			return
		}
		rho_j := bindingFactors[cm.Identifier.String()]
		commitShare, err := cm.Hiding.Add(cm.Binding.ScalarMult(rho_j))
		if err != nil {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("computing commitment_share for %s: %w", pid, err))
			return
		}
		lambda_j := frost.LagrangeCoefficient(cs, cm.Identifier, signerIDs)
		clambda := modQ.Mul(c, lambda_j)
		lhs := g.ScalarBaseMult(zj)
		rhs, err := commitShare.Add(Yj.ScalarMult(clambda))
		if err != nil {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("computing verifier rhs for %s: %w", pid, err))
			return
		}
		if !lhs.Equal(rhs) {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("partial signature from %s failed verification", pid))
			return
		}
		z = modQ.Add(z, zj)
	}

	rEnc := R.Bytes()
	sEnc := g.EncodeScalar(z)
	sig := make([]byte, 0, 64)
	sig = append(sig, rEnc...)
	sig = append(sig, sEnc...)

	pk := &edwards25519.PublicKey{
		Curve: s.params.EC(),
		X:     s.key.GroupPublicKey.X(),
		Y:     s.key.GroupPublicKey.Y(),
	}
	rBigInt := leBytesToBigInt(rEnc)
	sBigInt := leBytesToBigInt(sEnc)
	if !edwards25519.VerifyRS(pk, s.msg, rBigInt, sBigInt) {
		sendOnce(&s.errOnce, s.Err, fmt.Errorf("frosttss: aggregated signature failed local Ed25519 verification"))
		return
	}

	sendOnce(&s.doneOnce, s.Done, &SignatureData{
		R:         rEnc,
		S:         sEnc,
		Signature: sig,
		M:         s.msg,
	})
}

func leBytesToBigInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i, v := range le {
		be[len(le)-1-i] = v
	}
	return new(big.Int).SetBytes(be)
}
