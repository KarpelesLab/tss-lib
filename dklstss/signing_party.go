package dklstss

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/ole"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// SigningParty is the per-party signing state machine that runs over a
// tss.MessageBroker. Construction is symmetric: each signer in the
// chosen T+1 subset constructs its own *SigningParty against the same
// key, hash, and committee; the parties exchange messages via the
// broker and converge on the same ECDSA signature.
//
// Lifecycle:
//
//	Round 1: broadcast K_i = k_i · G to every other signer.
//	Round 2: for each peer j (Alice = self, Bob = j), unicast both
//	         ΠMul Alice envelopes (k·ρ and sx·ρ).
//	Round 3: for each peer j (Alice = j, Bob = self), unicast both
//	         ΠMul Bob responses (corrections + Bob's share contribution).
//	Round 4: broadcast (φ_i, ŝ_i).
//	Finalize: aggregate φ and ŝ; compute s = ŝ · φ⁻¹; emit Signature.
type SigningParty struct {
	ctx    context.Context
	params *tss.Parameters
	key    *Key
	hash   []byte
	tweak  *big.Int // optional HD tweak, nil for regular signing
	ssid   []byte

	// signing subset (sorted PartyIDs; this party is included).
	subset        tss.SortedPartyIDs
	myPos         int // index of self within subset
	otherSubset   []*tss.PartyID
	subsetIDs     []*big.Int
	lambdas       []*big.Int
	sxBySubsetIdx []*big.Int

	// local per-session randomness.
	k_i   *big.Int
	rho_i *big.Int
	K_i   *crypto.ECPoint
	r     *big.Int // R.x mod q, set after round 2 (when R is known)

	// per-peer Alice-side state for the two ΠMul kinds.
	aliceStateK map[string]*ole.AliceState
	aliceStateX map[string]*ole.AliceState

	// per-peer received K_j (from round 1) — needed only for R.
	peerK map[string]*crypto.ECPoint

	// share accumulators (indexed by subset position).
	kRhoShare []*big.Int
	xRhoShare []*big.Int

	// φ_i and ŝ_i computed locally after own shares are determined,
	// broadcast in round 4.
	phi_i  *big.Int
	shat_i *big.Int

	// round-4 collected from peers (subset).
	r4msgs map[string]*signR4

	Done chan *Signature
	Err  chan error

	// Once-guards on Done/Err — see once_send.go.
	doneOnce sync.Once
	errOnce  sync.Once
}

// NewSigning kicks off broker-driven signing for the local party. The
// subset parameter MUST contain exactly T+1 distinct party IDs from
// key.PartyIDs, sorted, and include the local party (key.PartyIDs[key.Idx]).
//
// hash is the message digest; tweak is the optional HD-derived tweak
// (nil for regular signing). Result lands on Done or Err.
func NewSigning(ctx context.Context, params *tss.Parameters, key *Key, hash []byte, subset tss.SortedPartyIDs, tweak *big.Int) (*SigningParty, error) {
	if ctx == nil || params == nil || key == nil {
		return nil, errors.New("dklstss: NewSigning nil argument")
	}
	if len(hash) == 0 {
		return nil, errors.New("dklstss: NewSigning empty hash")
	}
	if err := key.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("dklstss: NewSigning invalid key: %w", err)
	}
	if !tss.SameCurve(params.EC(), tss.S256()) {
		return nil, errors.New("dklstss: NewSigning requires secp256k1")
	}
	if len(subset) != key.T+1 {
		return nil, fmt.Errorf("dklstss: NewSigning subset size %d, expected T+1=%d", len(subset), key.T+1)
	}
	if err := validateSortedSubset(subset); err != nil {
		return nil, fmt.Errorf("dklstss: NewSigning %w", err)
	}

	// Locate self in subset.
	self := params.PartyID()
	myPos := -1
	for i, p := range subset {
		if p.KeyInt().Cmp(self.KeyInt()) == 0 {
			myPos = i
			break
		}
	}
	if myPos < 0 {
		return nil, fmt.Errorf("dklstss: NewSigning self not in subset")
	}

	ec := params.EC()
	q := ec.Params().N

	subsetIDs := make([]*big.Int, len(subset))
	for i, p := range subset {
		subsetIDs[i] = p.KeyInt()
	}
	lambdas := make([]*big.Int, len(subset))
	for i := range subset {
		lam, err := lagrangeCoefficient(q, subsetIDs, i)
		if err != nil {
			return nil, fmt.Errorf("dklstss: NewSigning lagrange: %w", err)
		}
		lambdas[i] = lam
	}

	// Compute sx for all subset members so we have a stable mapping
	// from subset-position to scaled-share — only sx[myPos] is the
	// local secret; the others are placeholders for indexing.
	sxBySubsetIdx := make([]*big.Int, len(subset))
	// Local scaled share λ_myPos · x_i mod q.
	sxBySubsetIdx[myPos] = new(big.Int).Mul(lambdas[myPos], key.Xi)
	sxBySubsetIdx[myPos].Mod(sxBySubsetIdx[myPos], q)
	if tweak != nil && myPos == 0 {
		t := new(big.Int).Mod(tweak, q)
		sxBySubsetIdx[myPos] = new(big.Int).Add(sxBySubsetIdx[myPos], t)
		sxBySubsetIdx[myPos].Mod(sxBySubsetIdx[myPos], q)
	}

	otherSubset := make([]*tss.PartyID, 0, len(subset)-1)
	for _, p := range subset {
		if p.KeyInt().Cmp(self.KeyInt()) != 0 {
			otherSubset = append(otherSubset, p)
		}
	}

	sp := &SigningParty{
		ctx:           ctx,
		params:        params,
		key:           key,
		hash:          append([]byte(nil), hash...),
		tweak:         tweak,
		ssid:          signSession(params, key, hash, subset),
		subset:        subset,
		myPos:         myPos,
		otherSubset:   otherSubset,
		subsetIDs:     subsetIDs,
		lambdas:       lambdas,
		sxBySubsetIdx: sxBySubsetIdx,
		aliceStateK:   make(map[string]*ole.AliceState),
		aliceStateX:   make(map[string]*ole.AliceState),
		peerK:         make(map[string]*crypto.ECPoint),
		kRhoShare:     make([]*big.Int, len(subset)),
		xRhoShare:     make([]*big.Int, len(subset)),
		r4msgs:        make(map[string]*signR4),
		Done:          make(chan *Signature, 1),
		Err:           make(chan error, 1),
	}
	for i := range sp.kRhoShare {
		sp.kRhoShare[i] = new(big.Int)
		sp.xRhoShare[i] = new(big.Int)
	}
	if err := sp.round1(); err != nil {
		return nil, fmt.Errorf("dklstss: NewSigning round1: %w", err)
	}
	return sp, nil
}

func (sp *SigningParty) round1() error {
	Pi := sp.params.PartyID()
	ec := sp.params.EC()
	q := ec.Params().N

	// Sample k_i, ρ_i.
	sp.k_i = common.GetRandomPositiveInt(sp.params.Rand(), q)
	sp.rho_i = common.GetRandomPositiveInt(sp.params.Rand(), q)
	sp.K_i = ctmul.ScalarBaseMultWithRand(ec, sp.k_i, sp.params.Rand())

	// Initialize own diagonal shares.
	// k_i, ρ_i, and sx_i are all per-party secret scalars (sx_i is
	// λ_i·Xi, the Lagrange-scaled threshold share). Their products are
	// later combined into the ŝ_i partial signature broadcast in round
	// 4; computing them via math/big.Int.Mul leaks bits through
	// timing. The CT mul-add primitive computes both products inside
	// the same CT path used by the Schnorr response.
	zero := new(big.Int)
	sp.kRhoShare[sp.myPos] = crypto.CTScalarMulAddModN(ec, sp.k_i, sp.rho_i, zero)
	sp.xRhoShare[sp.myPos] = crypto.CTScalarMulAddModN(ec, sp.sxBySubsetIdx[sp.myPos], sp.rho_i, zero)

	// Broadcast K_i to every peer in the subset via a single To==nil
	// message rather than N-1 unicasts. K_i has identical bytes for
	// every recipient by construction (it's the same point); sending
	// it as a broadcast lets a well-behaved broker enforce the "same
	// bytes to every recipient" contract that prevents equivocation
	// (a malicious party sending K_i_A to A and K_i_B to B). Matches
	// the broadcast convention already used in keygen / refresh /
	// resharing round 1 for the same reason.
	//
	// NOTE: a malicious BROKER could still equivocate by re-wrapping
	// the broadcast as different per-recipient unicasts. A defense-in-
	// depth echo-cross-check (each peer broadcasts a digest of every
	// K_j received and they're cross-verified) would close that gap;
	// see echo.go for the keygen analogue. For signing/presigning the
	// equivocation is currently caught downstream as an opaque ΠMul
	// failure (the mixed ssid diverges between Alice and Bob), so the
	// security goal holds but identifiable abort does not. The echo
	// extension is tracked separately.
	r1 := &signR1{KiX: sp.K_i.X().Bytes(), KiY: sp.K_i.Y().Bytes()}
	bcast := tss.JsonWrap(signTypeR1, r1, Pi, nil)
	if err := sp.params.Broker().Receive(bcast); err != nil {
		return fmt.Errorf("broker r1 bcast: %w", err)
	}
	rcv := tss.NewJsonExpect[signR1](signTypeR1, sp.otherSubset, sp.round2KCollect)
	sp.params.Broker().Connect(signTypeR1, rcv)
	return nil
}

// round2KCollect fires after every other signer's K_j has arrived.
// Decodes K_j, aggregates R, validates r != 0, then broadcasts a digest
// map of every party's K (self + peers) as an echo. The echo-cross-
// check round (round2Echo below) catches a malicious broker that ships
// different K_i bytes to different recipients with identifiable abort.
func (sp *SigningParty) round2KCollect(otherIds []*tss.PartyID, msgs []*signR1) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	ec := sp.params.EC()
	q := ec.Params().N
	Pi := sp.params.PartyID()

	// Process peer K_j and assemble R.
	R := sp.K_i
	for n, pid := range otherIds {
		Kj, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(msgs[n].KiX),
			new(big.Int).SetBytes(msgs[n].KiY))
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s sent invalid K_j: %w", pid, err),
				echoSourceSign, 0, nil, pid)))
			return
		}
		sp.peerK[peerKeyStr(pid)] = Kj
		Radd, err := R.Add(Kj)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("R aggregation: %w", err))
			return
		}
		R = Radd
	}
	r := new(big.Int).Mod(R.X(), q)
	if r.Sign() == 0 {
		sendOnce(&sp.errOnce, sp.Err, errors.New("R.X mod q == 0, retry with fresh randomness"))
		return
	}
	sp.r = r

	// Build my view of every signer's K as a digest map. Each entry is
	// digest(echoTagSign, dealer=P, [P.K.X, P.K.Y]). Don't include self —
	// verifyEchoes excludes self-as-dealer (the echoer's "view of itself"
	// is taken as canonical).
	digests := make(map[string][]byte, len(otherIds))
	for _, pid := range otherIds {
		Kj := sp.peerK[peerKeyStr(pid)]
		digests[peerKeyStr(pid)] = kIDigest(pid, Kj)
	}
	echoOut := &echoMsg{Digests: digests}
	echoBcast := tss.JsonWrap(signTypeR1Echo, echoOut, Pi, nil)
	if err := sp.params.Broker().Receive(echoBcast); err != nil {
		sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r1echo bcast: %w", err))
		return
	}

	rcv := tss.NewJsonExpect[echoMsg](signTypeR1Echo, sp.otherSubset,
		func(ids []*tss.PartyID, msgs []*echoMsgT) {
			sp.round2Echo(otherIds, ids, msgs)
		})
	sp.params.Broker().Connect(signTypeR1Echo, rcv)
}

// echoMsgT is a type alias so the JsonExpect helper resolves the
// generic without ambiguity vs. the package-level echoMsg type.
type echoMsgT = echoMsg

// round2Echo fires after every other signer's echo has arrived. Cross-
// checks every echo against the local digest view; a disagreement on
// some K_j surfaces as identifiable abort with the equivocator named in
// Culprits(). On success, mixes ssid and proceeds with Alice envelopes
// (the original round2 body).
func (sp *SigningParty) round2Echo(otherIds, echoers []*tss.PartyID, msgs []*echoMsg) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	Pi := sp.params.PartyID()

	// My local digest map for verifyEchoes:
	//   - For each peer dealer pid: digest of pid's K (computed in
	//     round2KCollect, recomputed here for clarity).
	//   - For self: digest of my own K_i.
	myDigests := make(map[string][]byte, len(otherIds)+1)
	for _, pid := range otherIds {
		Kj := sp.peerK[peerKeyStr(pid)]
		myDigests[peerKeyStr(pid)] = kIDigest(pid, Kj)
	}
	selfKey := peerKeyStr(Pi)
	myDigests[selfKey] = kIDigest(Pi, sp.K_i)

	// Echoers are the OTHER signers (sp.otherSubset). The "all parties"
	// list passed to verifyEchoes is [Pi] ++ otherIds — every party in
	// the signing subset.
	all := make([]*tss.PartyID, 0, len(otherIds)+1)
	all = append(all, Pi)
	all = append(all, otherIds...)
	if err := verifyEchoes(myDigests, selfKey, echoers, msgs, all, echoSourceSign); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}

	// Mix every signer's freshly-sampled K_i into the effective ssid for
	// round 2+. The OT extension state is reused across signings, so the
	// sid passed to ole.AliceStep1 / ole.BobStep1 (and through to the
	// per-call PRG derivation in crypto/ot/otext) MUST vary per call.
	// Without this, two signings of the same hash by the same subset
	// would produce identical sidK/sidX, the per-call PRG would yield
	// identical t0/t1 masks, and the receiver's wire message
	// u_j = t0[j] ⊕ t1[j] ⊕ bitsLE(α) would leak α¹⊕α² across the two
	// calls. K_i = k_i · G is uniformly random per signing for every
	// honest signer, so the combined hash is fresh with overwhelming
	// probability whenever at least one signer is honest.
	sp.ssid = mixRoundOneSsid(sp.ssid, Pi, sp.K_i, otherIds, sp.peerK)

	// For each peer j, this party plays Alice in two ΠMul instances:
	// (k_i, ρ_j) and (sx_i, ρ_j). Send Alice envelopes.
	for _, Pj := range sp.otherSubset {
		// Find Bob's per-pair OT-extension-receiver state on Alice's side.
		alicePair := sp.key.OT[sp.indexInFullCommittee(Pj)]
		if alicePair == nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("missing OT state with peer %s", Pj))
			return
		}
		sidK := signMulSid(sp.ssid, "kxrho", Pi.KeyInt(), Pj.KeyInt())
		sidX := signMulSid(sp.ssid, "xxrho", Pi.KeyInt(), Pj.KeyInt())

		msgK, stK, err := ole.AliceStep1(sidK, alicePair.AsAlice, sp.k_i)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("ΠMul-k Alice1 to %s: %w", Pj, err))
			return
		}
		msgX, stX, err := ole.AliceStep1(sidX, alicePair.AsAlice, sp.sxBySubsetIdx[sp.myPos])
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("ΠMul-x Alice1 to %s: %w", Pj, err))
			return
		}
		sp.aliceStateK[peerKeyStr(Pj)] = stK
		sp.aliceStateX[peerKeyStr(Pj)] = stX

		r2 := &signR2{
			AliceK: encodeExtendMsg(msgK),
			AliceX: encodeExtendMsg(msgX),
		}
		m := tss.JsonWrap(signTypeR2, r2, Pi, Pj)
		if err := sp.params.Broker().Receive(m); err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r2→%s: %w", Pj, err))
			return
		}
	}

	rcv := tss.NewJsonExpect[signR2](signTypeR2, sp.otherSubset, sp.round3)
	sp.params.Broker().Connect(signTypeR2, rcv)
}

func (sp *SigningParty) round3(otherIds []*tss.PartyID, msgs []*signR2) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	Pi := sp.params.PartyID()
	q := sp.params.EC().Params().N

	// Each peer sent us two Alice envelopes (treating self as Bob). Run
	// BobStep1 for each, send back Bob responses bundled in r3.
	for n, pid := range otherIds {
		r2 := msgs[n]
		bobPair := sp.key.OT[sp.indexInFullCommittee(pid)]
		if bobPair == nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("missing OT state with peer %s", pid))
			return
		}
		extMsgK, err := decodeExtendMsg(r2.AliceK)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("decode Alice k-envelope from %s: %w", pid, err))
			return
		}
		extMsgX, err := decodeExtendMsg(r2.AliceX)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("decode Alice x-envelope from %s: %w", pid, err))
			return
		}
		// peer's sid bound to peer-as-Alice
		sidK := signMulSid(sp.ssid, "kxrho", pid.KeyInt(), Pi.KeyInt())
		sidX := signMulSid(sp.ssid, "xxrho", pid.KeyInt(), Pi.KeyInt())

		bMsgK, uBK, err := ole.BobStep1(sidK, bobPair.AsBob, sp.rho_i, extMsgK)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("ΠMul-k Bob1 with %s: %w", pid, err))
			return
		}
		bMsgX, uBX, err := ole.BobStep1(sidX, bobPair.AsBob, sp.rho_i, extMsgX)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("ΠMul-x Bob1 with %s: %w", pid, err))
			return
		}

		// Accumulate Bob's shares against this party's accumulator —
		// these are shares of k_{peer} · ρ_i and sx_{peer} · ρ_i.
		sp.kRhoShare[sp.myPos] = addMod(q, sp.kRhoShare[sp.myPos], uBK)
		sp.xRhoShare[sp.myPos] = addMod(q, sp.xRhoShare[sp.myPos], uBX)

		r3 := &signR3{
			BobK: encodeBobMsg(bMsgK),
			BobX: encodeBobMsg(bMsgX),
		}
		m := tss.JsonWrap(signTypeR3, r3, Pi, pid)
		if err := sp.params.Broker().Receive(m); err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r3→%s: %w", pid, err))
			return
		}
	}

	rcv := tss.NewJsonExpect[signR3](signTypeR3, sp.otherSubset, sp.round4)
	sp.params.Broker().Connect(signTypeR3, rcv)
}

func (sp *SigningParty) round4(otherIds []*tss.PartyID, msgs []*signR3) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	Pi := sp.params.PartyID()
	q := sp.params.EC().Params().N

	// Each peer sent us Bob responses to our Alice envelopes — close
	// the loop with AliceStep2.
	for n, pid := range otherIds {
		r3 := msgs[n]
		stK := sp.aliceStateK[peerKeyStr(pid)]
		stX := sp.aliceStateX[peerKeyStr(pid)]
		if stK == nil || stX == nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("missing Alice state for peer %s", pid))
			return
		}
		bobMsgK, err := decodeBobMsg(r3.BobK)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("decode Bob-k from %s: %w", pid, err))
			return
		}
		bobMsgX, err := decodeBobMsg(r3.BobX)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("decode Bob-x from %s: %w", pid, err))
			return
		}
		uAK, err := ole.AliceStep2(stK, bobMsgK)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("ΠMul-k Alice2 with %s: %w", pid, err))
			return
		}
		uAX, err := ole.AliceStep2(stX, bobMsgX)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("ΠMul-x Alice2 with %s: %w", pid, err))
			return
		}
		sp.kRhoShare[sp.myPos] = addMod(q, sp.kRhoShare[sp.myPos], uAK)
		sp.xRhoShare[sp.myPos] = addMod(q, sp.xRhoShare[sp.myPos], uAX)
	}

	// Compute φ_i and ŝ_i — note that φ_i represents only THIS party's
	// portion of φ = Σ k_iρ_i + cross-terms; after broadcast and sum,
	// the global φ = k·ρ.
	// hashToScalar applies SEC 1 §4.1.3 leftmost-bits truncation so a
	// longer-than-curve-order digest still produces a stdlib-verifiable
	// signature.
	hashI := hashToScalar(q, sp.hash)
	sp.phi_i = new(big.Int).Set(sp.kRhoShare[sp.myPos])
	// ŝ_i = ρ_i·H + r·σ_i. Both ρ_i and σ_i (xRhoShare[myPos]) are
	// secret; route the two multiplications through the CT mul-add.
	ec := sp.params.EC()
	zero := new(big.Int)
	t1 := crypto.CTScalarMulAddModN(ec, sp.rho_i, hashI, zero)
	sp.shat_i = crypto.CTScalarMulAddModN(ec, sp.r, sp.xRhoShare[sp.myPos], t1)

	// Broadcast (φ_i, ŝ_i) as a single To==nil message rather than N-1
	// per-recipient unicasts. The bytes are identical for every recipient
	// by construction (this is THIS party's single partial-signature
	// contribution), so a broadcast lets a well-behaved broker enforce the
	// "same bytes to every recipient" contract — and the round-4 echo
	// cross-check below (round4Echo) catches a malicious broker (or party)
	// that ships different (φ_i, ŝ_i) to different signers, naming the
	// equivocator in Culprits() rather than failing as an opaque
	// verify-gate error. Mirrors the round-1 K_i echo (round2KCollect /
	// round2Echo).
	r4 := &signR4{Phi: sp.phi_i.Bytes(), Shat: sp.shat_i.Bytes()}
	bcast := tss.JsonWrap(signTypeR4, r4, Pi, nil)
	if err := sp.params.Broker().Receive(bcast); err != nil {
		sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r4 bcast: %w", err))
		return
	}
	rcv := tss.NewJsonExpect[signR4](signTypeR4, sp.otherSubset, sp.round5Echo)
	sp.params.Broker().Connect(signTypeR4, rcv)
}

// round5Echo fires after every other signer's (φ_j, ŝ_j) broadcast has
// arrived. It stashes the received contributions, then broadcasts a
// digest map of every peer's (φ_j, ŝ_j) as an echo. The echo-cross-check
// round (finalize below) catches a party that revealed different
// (φ_i, ŝ_i) to different signers with identifiable abort.
func (sp *SigningParty) round5Echo(otherIds []*tss.PartyID, msgs []*signR4) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	Pi := sp.params.PartyID()

	// Stash every peer's contribution keyed by party so finalize can sum
	// the canonical bytes this party actually received.
	digests := make(map[string][]byte, len(otherIds))
	for n, pid := range otherIds {
		sp.r4msgs[peerKeyStr(pid)] = msgs[n]
		digests[peerKeyStr(pid)] = r4Digest(pid, msgs[n])
	}
	echoOut := &echoMsg{Digests: digests}
	echoBcast := tss.JsonWrap(signTypeR4Echo, echoOut, Pi, nil)
	if err := sp.params.Broker().Receive(echoBcast); err != nil {
		sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r4echo bcast: %w", err))
		return
	}
	rcv := tss.NewJsonExpect[echoMsg](signTypeR4Echo, sp.otherSubset,
		func(ids []*tss.PartyID, ms []*echoMsg) {
			sp.finalize(otherIds, ids, ms)
		})
	sp.params.Broker().Connect(signTypeR4Echo, rcv)
}

func (sp *SigningParty) finalize(otherIds, echoers []*tss.PartyID, echoes []*echoMsg) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	q := sp.params.EC().Params().N
	Pi := sp.params.PartyID()

	// Cross-check every signer's round-4 reveal: a party that sent
	// different (φ_i, ŝ_i) to different peers is detected when the echoed
	// digests disagree, and named as the culprit. My local view:
	//   - for each peer dealer pid: digest of the (φ, ŝ) I received from pid.
	//   - for self: digest of my own (φ_i, ŝ_i).
	myDigests := make(map[string][]byte, len(otherIds)+1)
	for _, pid := range otherIds {
		myDigests[peerKeyStr(pid)] = r4Digest(pid, sp.r4msgs[peerKeyStr(pid)])
	}
	selfKey := peerKeyStr(Pi)
	myDigests[selfKey] = r4Digest(Pi, &signR4{Phi: sp.phi_i.Bytes(), Shat: sp.shat_i.Bytes()})
	all := append([]*tss.PartyID{Pi}, otherIds...)
	if err := verifyEchoes(myDigests, selfKey, echoers, echoes, all, echoSourceSign); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}

	phi := new(big.Int).Set(sp.phi_i)
	shat := new(big.Int).Set(sp.shat_i)
	for _, pid := range otherIds {
		m := sp.r4msgs[peerKeyStr(pid)]
		phi.Add(phi, new(big.Int).SetBytes(m.Phi))
		phi.Mod(phi, q)
		shat.Add(shat, new(big.Int).SetBytes(m.Shat))
		shat.Mod(shat, q)
	}
	if phi.Sign() == 0 {
		sendOnce(&sp.errOnce, sp.Err, errors.New("φ aggregated to 0; retry signing with fresh randomness"))
		return
	}
	phiInv := common.ModInt(q).ModInverse(phi)
	if phiInv == nil {
		sendOnce(&sp.errOnce, sp.Err, errors.New("φ has no inverse"))
		return
	}
	s := new(big.Int).Mul(shat, phiInv)
	s.Mod(s, q)
	if s.Sign() == 0 {
		sendOnce(&sp.errOnce, sp.Err, errors.New("s = 0; retry signing"))
		return
	}
	// Low-S normalization.
	halfQ := new(big.Int).Rsh(q, 1)
	// We need R's Y-bit; reconstruct R = sum of K_i.
	R := sp.K_i
	for _, pid := range sp.otherSubset {
		Rp, err := R.Add(sp.peerK[peerKeyStr(pid)])
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("R reconstruct: %w", err))
			return
		}
		R = Rp
	}
	v := byte(R.Y().Bit(0))
	if s.Cmp(halfQ) > 0 {
		s.Sub(q, s)
		v ^= 1
	}
	rOut := new(big.Int).Set(sp.r)
	// Final self-verification gate (see signing.go): a malicious round-4
	// (φ_i, ŝ_i) reveal or corrupt share can otherwise drive this party to
	// emit a non-verifying signature on Done. Reject it instead.
	if err := verifyFinalSignature(sp.key.ECDSAPub, sp.tweak, sp.hash, rOut, s); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	sendOnce(&sp.doneOnce, sp.Done, &Signature{R: rOut, S: s, V: v})
}

// --- helpers --------------------------------------------------------

func (sp *SigningParty) indexInFullCommittee(p *tss.PartyID) int {
	for i, q := range sp.key.PartyIDs {
		if q.KeyInt().Cmp(p.KeyInt()) == 0 {
			return i
		}
	}
	return -1
}

func signSession(params *tss.Parameters, key *Key, hash []byte, subset tss.SortedPartyIDs) []byte {
	h := sha256.New()
	h.Write([]byte("DKLS23-sign-party-v1-"))
	h.Write(key.ECDSAPub.X().Bytes())
	h.Write(key.ECDSAPub.Y().Bytes())
	h.Write(hash)
	for _, p := range subset {
		h.Write(p.KeyInt().Bytes())
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

func signMulSid(ssid []byte, kind string, alice, bob *big.Int) []byte {
	h := sha256.New()
	h.Write(ssid)
	h.Write([]byte{'|'})
	h.Write([]byte(kind))
	h.Write([]byte{'|'})
	h.Write(alice.Bytes())
	h.Write([]byte{'|'})
	h.Write(bob.Bytes())
	return h.Sum(nil)
}

// mixRoundOneSsid combines the per-call random round-1 contributions
// (each signer's K_i point) into the static ssid to produce an effective
// ssid that's freshly random per signing call. Used by SigningParty and
// PresignParty to make the ΠMul sid passed to the OT-extension layer
// vary per call, which is required to prevent OT-extension seed reuse
// from leaking choice bits — see crypto/ot/otext/prg.go for the matching
// per-call PRG derivation.
//
// The hash sorts by party key-int so every honest party computes the
// same value regardless of message-arrival order.
func mixRoundOneSsid(baseSsid []byte, selfID *tss.PartyID, selfK *crypto.ECPoint, peerIDs []*tss.PartyID, peerK map[string]*crypto.ECPoint) []byte {
	type idK struct {
		id *big.Int
		k  *crypto.ECPoint
	}
	all := make([]idK, 0, len(peerIDs)+1)
	all = append(all, idK{id: selfID.KeyInt(), k: selfK})
	for _, pid := range peerIDs {
		k, ok := peerK[peerKeyStr(pid)]
		if !ok || k == nil {
			continue
		}
		all = append(all, idK{id: pid.KeyInt(), k: k})
	}
	// Sort by id (ascending big-int).
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j-1].id.Cmp(all[j].id) > 0; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	h := sha256.New()
	h.Write([]byte("DKLS23-sign-ssid-mix-v1"))
	h.Write([]byte{'|'})
	h.Write(baseSsid)
	for _, e := range all {
		h.Write([]byte{'|'})
		h.Write(e.id.Bytes())
		h.Write([]byte{'|'})
		h.Write(e.k.X().Bytes())
		h.Write([]byte{'|'})
		h.Write(e.k.Y().Bytes())
	}
	return h.Sum(nil)
}

// --- wire types -----------------------------------------------------

type signR1 struct {
	KiX []byte `json:"k_i_x"`
	KiY []byte `json:"k_i_y"`
}

type signR2 struct {
	AliceK *encodedExtendMsg `json:"alice_k"`
	AliceX *encodedExtendMsg `json:"alice_x"`
}

type signR3 struct {
	BobK [][]byte `json:"bob_k"`
	BobX [][]byte `json:"bob_x"`
}

type signR4 struct {
	Phi  []byte `json:"phi"`
	Shat []byte `json:"shat"`
}

const (
	signTypeR1     = "dkls:sign:r1"
	signTypeR1Echo = "dkls:sign:r1echo" // echo-broadcast phase for K_i equivocation defense
	signTypeR2     = "dkls:sign:r2"
	signTypeR3     = "dkls:sign:r3"
	signTypeR4     = "dkls:sign:r4"
	signTypeR4Echo = "dkls:sign:r4echo" // echo-broadcast phase for (φ_i, ŝ_i) equivocation defense

	echoTagSign    = "DKLS23-echo-sign-v1"
	echoTagSignR4  = "DKLS23-echo-sign-r4-v1"
	echoSourceSign = "dklstss-sign"
)

// r4Digest computes the echo-broadcast digest for one party's round-4
// (φ, ŝ) partial-signature reveal. Reuses commitDigest with a distinct
// round-4 sign-phase tag so a digest from this phase can never collide
// with a round-1 K_i digest. Phi and Shat are length-prefixed inside
// commitDigest, so swapping the two fields or an unusual byte length
// would not produce the same digest.
func r4Digest(dealer *tss.PartyID, r4 *signR4) []byte {
	return commitDigest(echoTagSignR4, dealer, [][]byte{r4.Phi, r4.Shat})
}

// kIDigest computes the echo-broadcast digest for one party's K_i =
// k_i*G commitment. Reuses commitDigest with the sign-phase tag.
// vsBytes is the (X, Y) coordinate pair of K, length-prefixed inside
// commitDigest so a coordinate swap or unusual byte length would not
// produce the same digest.
func kIDigest(dealer *tss.PartyID, K *crypto.ECPoint) []byte {
	return commitDigest(echoTagSign, dealer, [][]byte{K.X().Bytes(), K.Y().Bytes()})
}

// encodedExtendMsg is the wire form of otext.ExtendMsg1.
type encodedExtendMsg struct {
	L int      `json:"l"`
	U [][]byte `json:"u"`
	X []byte   `json:"x_check"`
	T [][]byte `json:"t_check"`
}

func encodeExtendMsg(m *otext.ExtendMsg1) *encodedExtendMsg {
	out := &encodedExtendMsg{L: m.L, U: m.U, X: m.X[:]}
	out.T = make([][]byte, len(m.T))
	for i, row := range m.T {
		out.T[i] = append([]byte(nil), row[:]...)
	}
	return out
}

func decodeExtendMsg(e *encodedExtendMsg) (*otext.ExtendMsg1, error) {
	if e == nil {
		return nil, errors.New("nil encodedExtendMsg")
	}
	if len(e.X) != otext.SigmaBytes {
		return nil, fmt.Errorf("X length %d, expected %d", len(e.X), otext.SigmaBytes)
	}
	if len(e.T) != otext.Sigma {
		return nil, fmt.Errorf("T length %d, expected %d", len(e.T), otext.Sigma)
	}
	m := &otext.ExtendMsg1{L: e.L, U: e.U}
	copy(m.X[:], e.X)
	for i := range e.T {
		if len(e.T[i]) != otext.DeltaBytes {
			return nil, fmt.Errorf("T[%d] length %d, expected %d", i, len(e.T[i]), otext.DeltaBytes)
		}
		copy(m.T[i][:], e.T[i])
	}
	return m, nil
}

func encodeBobMsg(b *ole.BobMsg) [][]byte {
	out := make([][]byte, len(b.Corrections))
	for i, c := range b.Corrections {
		out[i] = c.Bytes()
	}
	return out
}

func decodeBobMsg(in [][]byte) (*ole.BobMsg, error) {
	corrections := make([]*big.Int, len(in))
	for i, b := range in {
		corrections[i] = new(big.Int).SetBytes(b)
	}
	return &ole.BobMsg{Corrections: corrections}, nil
}
