package frosttss

import (
	"context"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Signing tracks a threshold FROST(Ed25519) signing operation. It implements
// the two-round non-coordinator signing protocol from RFC 9591 §5: a
// preprocessing round broadcasts each signer's nonce commitments (D_i, E_i),
// then a sign round broadcasts the partial scalar z_i. The aggregator (which
// in this non-coordinator design is every party) sums z_i and outputs the
// (R, S) Ed25519 signature.
type Signing struct {
	ctx     context.Context
	params  *tss.Parameters
	key     *Key
	msg     []byte

	// preprocessing nonces (round 1)
	di, ei      *big.Int       // hiding and binding nonces
	Di, Ei      *crypto.ECPoint // commitments d_i*G, e_i*G

	Done chan *SignatureData
	Err  chan error
}

// NewSigning starts a FROST(Ed25519) signing session against the message msg.
//
// The receiver key may have been produced by a keygen that involved more
// parties than the current signing committee; NewSigning transparently
// reindexes Ks and BigXj to match params.Parties().IDs() via SubsetForParties,
// so callers can pass the full keygen key as-is.
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
// broadcasts them. RFC 9591 §5.1 / §4.1.
func (s *Signing) round1() error {
	Pi := s.params.PartyID()
	i := Pi.Index
	ec := s.params.EC()

	s.di = common.GetRandomPositiveInt(s.params.Rand(), ec.Params().N)
	s.ei = common.GetRandomPositiveInt(s.params.Rand(), ec.Params().N)
	s.Di = crypto.ScalarBaseMult(ec, s.di)
	s.Ei = crypto.ScalarBaseMult(ec, s.ei)

	var otherIds []*tss.PartyID
	for n, p := range s.params.Parties().IDs() {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	r1 := &signRound1msg{
		Hiding:  frost.EncodeElement(s.Di),
		Binding: frost.EncodeElement(s.Ei),
	}
	for _, p := range otherIds {
		m := tss.JsonWrap("frost:ed25519:sign:round1", r1, Pi, p)
		s.params.Broker().Receive(m)
	}

	rcv := tss.NewJsonExpect[signRound1msg]("frost:ed25519:sign:round1", otherIds, s.round2)
	s.params.Broker().Connect("frost:ed25519:sign:round1", rcv)
	return nil
}

// round2 assembles the full nonce-commitment list, derives binding factors,
// computes the group commitment R and challenge c, computes the partial
// signature z_i, and broadcasts it.
func (s *Signing) round2(otherIds []*tss.PartyID, r1msgs []*signRound1msg) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	Pi := s.params.PartyID()
	ec := s.params.EC()

	// Build commitment list including self.
	commitments := make([]frost.NonceCommitment, 0, len(otherIds)+1)
	commitments = append(commitments, frost.NonceCommitment{
		Identifier: Pi.KeyInt(),
		Hiding:     s.Di,
		Binding:    s.Ei,
	})
	for n, pid := range otherIds {
		Dj, err := frost.DecodeElement(r1msgs[n].Hiding)
		if err != nil {
			s.Err <- fmt.Errorf("party %s sent invalid hiding commitment: %w", pid, err)
			return
		}
		Ej, err := frost.DecodeElement(r1msgs[n].Binding)
		if err != nil {
			s.Err <- fmt.Errorf("party %s sent invalid binding commitment: %w", pid, err)
			return
		}
		// Cofactor-clear in case of malicious-but-on-curve points.
		Dj = Dj.EightInvEight()
		Ej = Ej.EightInvEight()
		commitments = append(commitments, frost.NonceCommitment{
			Identifier: pid.KeyInt(),
			Hiding:     Dj,
			Binding:    Ej,
		})
	}

	bindingFactors := frost.ComputeBindingFactors(s.msg, commitments)
	R, err := frost.ComputeGroupCommitment(commitments, bindingFactors)
	if err != nil {
		s.Err <- fmt.Errorf("ComputeGroupCommitment: %w", err)
		return
	}
	c := frost.ComputeGroupChallenge(R, s.key.GroupPublicKey, s.msg)

	// Lagrange coefficient for self among the signing set.
	signerIDs := make([]*big.Int, 0, len(commitments))
	for _, cm := range commitments {
		signerIDs = append(signerIDs, cm.Identifier)
	}
	lambda_i := frost.LagrangeCoefficient(Pi.KeyInt(), signerIDs)

	// z_i = d_i + e_i * rho_i + lambda_i * s_i * c (mod L)
	rho_i := bindingFactors[Pi.KeyInt().String()]
	modQ := common.ModInt(ec.Params().N)
	term1 := s.di
	term2 := modQ.Mul(s.ei, rho_i)
	term3 := modQ.Mul(modQ.Mul(lambda_i, s.key.Xi), c)
	zi := modQ.Add(modQ.Add(term1, term2), term3)

	// Broadcast z_i.
	r2 := &signRound2msg{Z: frost.EncodeScalar(zi)}
	for _, p := range otherIds {
		m := tss.JsonWrap("frost:ed25519:sign:round2", r2, Pi, p)
		s.params.Broker().Receive(m)
	}

	// Register receiver for round 2 partial signatures. Pass through the data
	// we'll need at finalize time so the callback doesn't have to recompute it.
	rcv := tss.NewJsonExpect[signRound2msg]("frost:ed25519:sign:round2", otherIds, func(ids []*tss.PartyID, msgs []*signRound2msg) {
		s.finalize(commitments, bindingFactors, R, c, zi, otherIds, ids, msgs)
	})
	s.params.Broker().Connect("frost:ed25519:sign:round2", rcv)
}

// finalize verifies each peer's partial signature against their verification
// share and binding factor (RFC 9591 §5.2 step "verifySignatureShare"), sums
// the partials, and emits the final (R, S) signature.
func (s *Signing) finalize(
	commitments []frost.NonceCommitment,
	bindingFactors map[string]*big.Int,
	R *crypto.ECPoint,
	c *big.Int,
	myZi *big.Int,
	otherIds []*tss.PartyID,
	r2Ids []*tss.PartyID,
	r2msgs []*signRound2msg,
) {
	if s.ctx.Err() != nil {
		s.Err <- s.ctx.Err()
		return
	}
	ec := s.params.EC()
	modQ := common.ModInt(ec.Params().N)

	// Lookup map party identifier -> BigXj for the current signing committee.
	// key.BigXj is in current-party-index order because SubsetForParties has
	// already reindexed it.
	bigXByID := make(map[string]*crypto.ECPoint, len(s.key.BigXj))
	for j, kj := range s.key.Ks {
		bigXByID[kj.String()] = s.key.BigXj[j]
	}

	// Lookup map identifier -> nonce commitment.
	commitByID := make(map[string]frost.NonceCommitment, len(commitments))
	for _, cm := range commitments {
		commitByID[cm.Identifier.String()] = cm
	}

	// Build signer list for Lagrange coefficient computation.
	signerIDs := make([]*big.Int, 0, len(commitments))
	for _, cm := range commitments {
		signerIDs = append(signerIDs, cm.Identifier)
	}

	// Verify every peer's partial signature, then sum.
	z := new(big.Int).Set(myZi)
	for n, pid := range r2Ids {
		zj, err := frost.DecodeScalar(r2msgs[n].Z)
		if err != nil {
			s.Err <- fmt.Errorf("party %s sent invalid z: %w", pid, err)
			return
		}
		// verifySignatureShare(pid, zj):
		//   commitment_share = D_j + rho_j * E_j
		//   lambda_j = LagrangeCoefficient(pid, signers)
		//   Y_j = BigXj[j]
		//   check: z_j * G == commitment_share + (c * lambda_j) * Y_j
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
		lambda_j := frost.LagrangeCoefficient(cm.Identifier, signerIDs)
		clambda := modQ.Mul(c, lambda_j)
		lhs := crypto.ScalarBaseMult(ec, zj)
		rhs, err := commitShare.Add(Yj.ScalarMult(clambda))
		if err != nil {
			s.Err <- fmt.Errorf("computing verifier rhs for %s: %w", pid, err)
			return
		}
		if !lhs.Equals(rhs) {
			s.Err <- fmt.Errorf("partial signature from %s failed verification", pid)
			return
		}
		z = modQ.Add(z, zj)
	}

	// Compose the 64-byte signature.
	rEnc := frost.EncodeElement(R)
	sEnc := frost.EncodeScalar(z)
	sig := make([]byte, 0, 64)
	sig = append(sig, rEnc...)
	sig = append(sig, sEnc...)

	// Self-verify under a standard Ed25519 verifier to catch encoding or
	// signing errors before delivering to the caller.
	pk := &edwards25519.PublicKey{
		Curve: ec,
		X:     s.key.GroupPublicKey.X(),
		Y:     s.key.GroupPublicKey.Y(),
	}
	rBigInt := leBytesToBigInt(rEnc)
	sBigInt := leBytesToBigInt(sEnc)
	if !edwards25519.VerifyRS(pk, s.msg, rBigInt, sBigInt) {
		s.Err <- fmt.Errorf("frosttss: aggregated signature failed local Ed25519 verification")
		return
	}

	s.Done <- &SignatureData{
		R:         rEnc,
		S:         sEnc,
		Signature: sig,
		M:         s.msg,
	}
	_ = otherIds // silence unused; kept in signature for documentation symmetry with round2.
}

// leBytesToBigInt interprets a little-endian byte slice as an unsigned big.Int.
func leBytesToBigInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i, v := range le {
		be[len(le)-1-i] = v
	}
	return new(big.Int).SetBytes(be)
}
