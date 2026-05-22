package frosttss

import (
	"context"
	"fmt"
	"math/big"
	"sync"

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

	// HD derivation tweak (optional). When non-nil, the signature is
	// produced under the child public key derivedPub = key.GroupPublicKey
	// + tweak·G. Signer at subset index 0 absorbs the tweak into its
	// λ·s mul-add; every party uses derivedPub when computing the FROST
	// challenge c. Nil for non-HD signings — round flow is otherwise
	// identical.
	tweak      *big.Int
	derivedPub *crypto.ECPoint

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
	return key.NewSigningWithTweak(ctx, msg, params, nil)
}

// NewSigningWithTweak starts a FROST(Ed25519) signing session that
// produces a signature verifiable under the child public key
// key.GroupPublicKey + tweak·G. The tweak is the integer returned by
// DeriveChild for a chosen non-hardened path; passing nil reduces to
// NewSigning (signature verifies under key.GroupPublicKey).
//
// All signing parties must call this with the same tweak value, derived
// independently from the agreed (path, key) — there is no in-band
// transport for tweak. Mismatched tweaks across parties produce a
// signature that fails verification under both parent and child keys
// and triggers each party's local Ed25519 verify check at finalize.
//
// Convention: signer at subset index 0 (lowest ShareID in
// params.Parties()) absorbs tweak into its λ·s mul-add. The choice is
// deterministic from the sorted party set, so every party derives it
// the same way without coordination.
func (key *Key) NewSigningWithTweak(ctx context.Context, msg []byte, params *tss.Parameters, tweak *big.Int) (*Signing, error) {
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
	if tweak != nil {
		// Pre-compute the child public key once, used both for the FROST
		// challenge in round 2 and the partial-signature / final
		// verification in finalize.
		ec := frost.EdwardsCurve()
		L := ec.Params().N
		t := new(big.Int).Mod(tweak, L)
		if t.Sign() == 0 {
			// Tweak ≡ 0 mod L is equivalent to no tweak; collapse to the
			// non-HD path to avoid a wasteful empty add.
			s.tweak = nil
		} else {
			deltaG := crypto.CTScalarBaseMultEd25519(ec, t)
			derived, err := key.GroupPublicKey.Add(deltaG)
			if err != nil {
				return nil, fmt.Errorf("frosttss: NewSigningWithTweak: deriving child pubkey: %w", err)
			}
			if derived.IsIdentity() {
				return nil, fmt.Errorf("frosttss: NewSigningWithTweak: tweak collapses child to identity (tweak ≡ -parent_scalar mod L)")
			}
			s.tweak = t
			s.derivedPub = derived
		}
	}
	if err := s.round1(); err != nil {
		return nil, err
	}
	return s, nil
}

// DeriveAndSign is a convenience wrapper: it walks the BIP32-shape
// non-hardened path against key.ChainCode, then starts a signing
// session under the derived child key.
//
// Returns the running *Signing (whose Done emits a SignatureData
// verifiable under childPub) and the childPub itself, so the caller
// can hand it to an Ed25519 verifier.
//
// Hardened indices in the path return ErrHardenedNotSupported.
func (key *Key) DeriveAndSign(ctx context.Context, path []uint32, msg []byte, params *tss.Parameters) (*Signing, *crypto.ECPoint, error) {
	tweak, childPub, _, err := key.DeriveChild(path)
	if err != nil {
		return nil, nil, err
	}
	sig, err := key.NewSigningWithTweak(ctx, msg, params, tweak)
	if err != nil {
		return nil, nil, err
	}
	return sig, childPub, nil
}

// round1 samples nonces (d_i, e_i), computes commitments (D_i, E_i), and
// broadcasts them.
func (s *Signing) round1() error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	Pi := s.params.PartyID()
	i := Pi.Index
	_ = group.Ed25519() // retained for symmetry; ciphersuite drives the math

	// RFC 9591 §4.1: nonce_generate(secret) = H3(random_bytes ||
	// G.SerializeScalar(secret)). Mixing the share Xi into each nonce
	// derivation defangs a faulty/repeated RNG: if rand returns the same
	// bytes twice, the share-binding still produces distinct nonces (as
	// long as Xi differs across calls — and Xi is per-key, not per-call,
	// so reuse of the SAME Key with a repeating RNG over different
	// messages still yields distinct (d, e) per call because the random
	// bytes are mixed in too). The full defense is: "either rand or
	// secret must differ across calls" — substantially weaker than the
	// pre-fix "rand must never repeat."
	di, err := frost.NonceGenerate(frost.Ed25519Ciphersuite(), s.params.Rand(), s.key.Xi)
	if err != nil {
		return fmt.Errorf("frosttss: nonce_generate d_i: %w", err)
	}
	ei, err := frost.NonceGenerate(frost.Ed25519Ciphersuite(), s.params.Rand(), s.key.Xi)
	if err != nil {
		return fmt.Errorf("frosttss: nonce_generate e_i: %w", err)
	}
	s.di = di
	s.ei = ei
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
	// Challenge is over the public key the verifier will use: derived
	// child pubkey when HD-signing, parent group pubkey otherwise.
	// Every signing party performs this branch identically because tweak
	// is supplied identically at NewSigningWithTweak.
	challengePub := s.key.GroupPublicKey
	if s.tweak != nil {
		challengePub = s.derivedPub
	}
	groupPubEl := group.AdaptECPoint(challengePub)
	c := frost.ComputeGroupChallenge(cs, R, groupPubEl, s.msg)

	signerIDs := make([]*big.Int, 0, len(commitments))
	for _, cm := range commitments {
		signerIDs = append(signerIDs, cm.Identifier)
	}
	lambda_i := frost.LagrangeCoefficient(cs, Pi.KeyInt(), signerIDs)

	// z_i = d_i + e_i · ρ_i + λ_i · s_i · c (mod L)   [non-HD]
	// z_0 = d_0 + e_0 · ρ_0 + (λ_0 · s_0 + tweak) · c [HD, signer-0]
	// z_j = d_j + e_j · ρ_j + λ_j · s_j · c           [HD, signer j>0]
	//
	// Σ z_i = d_R + e_R · ρ_R + c · (Σ λ·s + tweak) =
	//       = d_R + e_R · ρ_R + c · child_priv  ✓
	//
	// Both nonces (d_i, e_i) and the share s_i are secret. Composing the
	// product `λ_i · s_i · c` through math/big.Int.Mul leaks bits of s_i;
	// composing `e_i · ρ_i` leaks bits of e_i. Re-express the expression
	// as a sequence of constant-time mul-add operations via
	// crypto.CTScalarMulAddModN (which routes through edwards25519.ScMulAdd
	// on Ed25519 — the same primitive RFC 8032 stdlib EdDSA uses):
	//
	//   t1 = e_i · ρ_i + d_i           (secret · public + secret)
	//   t2 = λ_i · s_i + tweakTerm     (public · secret + public)
	//   z_i = t2 · c + t1              (secret · public + secret)
	//
	// where tweakTerm is `s.tweak` for the signer at subset index 0 and
	// zero for everyone else. Adding a public scalar (tweak) into the
	// `+c` slot of CT mul-add does not leak the secret operand.
	rho_i := bindingFactors[Pi.KeyInt().String()]
	ec := frost.EdwardsCurve()
	tweakTerm := new(big.Int)
	if s.tweak != nil && Pi.Index == 0 {
		tweakTerm.Set(s.tweak)
	}
	t1 := crypto.CTScalarMulAddModN(ec, s.ei, rho_i, s.di)
	t2 := crypto.CTScalarMulAddModN(ec, lambda_i, s.key.Xi, tweakTerm)
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

	// HD: subset signer-0 (lowest ShareID) absorbed the tweak. When
	// verifying that party's partial, the RHS is augmented by c·tweak·G.
	// Compute the augment point once.
	var tweakDeltaEl group.Element
	var signer0ID string
	if s.tweak != nil {
		ec := frost.EdwardsCurve()
		tweakDeltaEl = group.AdaptECPoint(crypto.CTScalarBaseMultEd25519(ec, s.tweak))
		signer0ID = s.params.Parties().IDs()[0].KeyInt().String()
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
		// HD signer-0 augmentation: if this peer is the subset's lowest
		// ShareID, its z_j absorbed `tweak` into λ·s, so its partial
		// satisfies z_j·G = D_j + ρ_j·E_j + c·(λ·Y_j + tweak·G).
		if s.tweak != nil && cm.Identifier.String() == signer0ID {
			rhs, err = rhs.Add(tweakDeltaEl.ScalarMult(c))
			if err != nil {
				sendOnce(&s.errOnce, s.Err, fmt.Errorf("computing HD tweak augment for %s: %w", pid, err))
				return
			}
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

	verifyPub := s.key.GroupPublicKey
	if s.tweak != nil {
		verifyPub = s.derivedPub
	}
	pk := &edwards25519.PublicKey{
		Curve: s.params.EC(),
		X:     verifyPub.X(),
		Y:     verifyPub.Y(),
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
