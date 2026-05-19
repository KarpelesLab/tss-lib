package dklstss

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// RefreshParty is the broker-driven proactive refresh: each existing
// party participates with their old Key, the protocol exchanges
// zero-constant VSS shares plus fresh pairwise OT setup, and emits a
// new Key with rotated shares and OT state. The joint public key is
// unchanged.
//
// Rounds:
//
//	Round 1: unicast per peer of (VSS commitments to zero-constant
//	         polynomial, share evaluated at peer ID, base-OT-Sender msg
//	         for the direction where peer becomes ExtSender).
//	Round 2: unicast per peer of base-OT-Receiver R-points (for the
//	         direction where self becomes ExtSender).
//	Finalize: assemble new Key.
type RefreshParty struct {
	ctx    context.Context
	params *tss.Parameters
	old    *Key
	ssid   []byte

	coeffs []*big.Int        // a_{i,1}..a_{i,T}
	vsSelf []*crypto.ECPoint // T entries: V_{i,k} = a_{i,k} · G

	// own evaluations of f_i(j) for every peer j (incl. self).
	myShares map[string]*big.Int

	// per-peer base-OT state.
	baseSnd map[string]*baseot.Sender
	baseRcv map[string]*baseot.Receiver
	myDelta map[string][]byte

	// peer round-1 inputs.
	peerVs     map[string][]*crypto.ECPoint
	peerShares map[string]*big.Int

	// Round-1 join state. Like KeygenParty, the VSS commitments arrive
	// as a broadcast and the share + OT-base-sender material arrives
	// as a unicast; the echo phase cannot run until both halves are
	// complete. The atomic counter goes 0 → 1 → 2 and the goroutine
	// that reaches 2 drives the transition. See dklstss/keygen_party.go
	// for the rationale (H-3 equivocation defense + echo-broadcast).
	r1JoinCount atomic.Int32
	r1Bcasts    []*refreshR1Bcast
	r1Unicasts  []*refreshR1Unicast
	r1OtherIds  []*tss.PartyID

	// Echo phase: see keygen_party.go.
	r1Echoes []*echoMsg

	Done chan *Key
	Err  chan error

	// Once-guards on Done/Err — see once_send.go.
	doneOnce sync.Once
	errOnce  sync.Once
}

// NewRefresh kicks off broker-driven proactive refresh for the local
// party. Each refresh participant constructs its own *RefreshParty with
// its own old Key; the parties exchange messages via params.Broker()
// and converge on a fresh per-party Key.
func NewRefresh(ctx context.Context, params *tss.Parameters, oldKey *Key) (*RefreshParty, error) {
	if ctx == nil || params == nil || oldKey == nil {
		return nil, errors.New("dklstss: NewRefresh nil argument")
	}
	if err := oldKey.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("dklstss: NewRefresh invalid key: %w", err)
	}
	if !tss.SameCurve(params.EC(), tss.S256()) {
		return nil, errors.New("dklstss: NewRefresh requires secp256k1")
	}
	rp := &RefreshParty{
		ctx:        ctx,
		params:     params,
		old:        oldKey,
		ssid:       refreshSession(params, oldKey),
		baseSnd:    make(map[string]*baseot.Sender),
		baseRcv:    make(map[string]*baseot.Receiver),
		myDelta:    make(map[string][]byte),
		peerVs:     make(map[string][]*crypto.ECPoint),
		peerShares: make(map[string]*big.Int),
		myShares:   make(map[string]*big.Int),
		Done:       make(chan *Key, 1),
		Err:        make(chan error, 1),
	}
	if err := rp.round1(); err != nil {
		return nil, fmt.Errorf("dklstss: NewRefresh round1: %w", err)
	}
	return rp, nil
}

func (rp *RefreshParty) round1() error {
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	threshold := rp.old.T
	q := ec.Params().N

	// Sample T coefficients (no constant term).
	rp.coeffs = make([]*big.Int, threshold)
	rp.vsSelf = make([]*crypto.ECPoint, threshold)
	for k := 0; k < threshold; k++ {
		rp.coeffs[k] = common.GetRandomPositiveInt(rp.params.PartialKeyRand(), q)
		rp.vsSelf[k] = crypto.ScalarBaseMult(ec, rp.coeffs[k])
	}

	// Evaluate f_i(j) for every party j (incl. self).
	for _, p := range rp.params.Parties().IDs() {
		rp.myShares[peerKeyStr(p)] = evalZeroConstPoly(rp.coeffs, p.KeyInt(), q)
	}

	encVs := flattenPointXY(rp.vsSelf)
	otherIds := otherPartyIDs(rp.params)
	rp.r1OtherIds = otherIds

	// BROADCAST: zero-constant-term Vs commitments (identical to every
	// peer). H-3 equivocation defense — see keygen_party.go round1 for
	// the broker-contract rationale.
	bcast := &refreshR1Bcast{VSSCommitments: encVs}
	bm := tss.JsonWrap(refreshTypeR1Bcast, bcast, Pi, nil)
	if err := rp.params.Broker().Receive(bm); err != nil {
		return fmt.Errorf("broker r1-bcast: %w", err)
	}

	// UNICAST: per-peer share + base-OT-Sender material.
	for _, Pj := range otherIds {
		shareForJ := rp.myShares[peerKeyStr(Pj)]
		// Direction "j becomes ExtSender, i becomes ExtReceiver":
		// base-OT roles → i is base-OT Sender.
		sid := pairBaseSid(rp.ssid, Pi.KeyInt(), Pj.KeyInt(), Pj.KeyInt())
		snd, sndMsg, err := baseot.NewSender(sid, otext.Kappa, rp.params.Rand())
		if err != nil {
			return fmt.Errorf("baseot.NewSender for %s: %w", Pj, err)
		}
		rp.baseSnd[peerKeyStr(Pj)] = snd

		uc := &refreshR1Unicast{
			Share:         shareForJ.Bytes(),
			OTSenderSX:    sndMsg.S.X().Bytes(),
			OTSenderSY:    sndMsg.S.Y().Bytes(),
			OTSenderPokAX: sndMsg.PoK.Alpha.X().Bytes(),
			OTSenderPokAY: sndMsg.PoK.Alpha.Y().Bytes(),
			OTSenderPokT:  sndMsg.PoK.T.Bytes(),
		}
		m := tss.JsonWrap(refreshTypeR1Unicast, uc, Pi, Pj)
		if err := rp.params.Broker().Receive(m); err != nil {
			return fmt.Errorf("broker r1-uc→%s: %w", Pj, err)
		}
	}
	rcvBcast := tss.NewJsonExpect[refreshR1Bcast](refreshTypeR1Bcast, otherIds, rp.onR1Bcast)
	rcvUnicast := tss.NewJsonExpect[refreshR1Unicast](refreshTypeR1Unicast, otherIds, rp.onR1Unicast)
	rp.params.Broker().Connect(refreshTypeR1Bcast, rcvBcast)
	rp.params.Broker().Connect(refreshTypeR1Unicast, rcvUnicast)
	return nil
}

// onR1Bcast / onR1Unicast: see keygen_party.go for the join semantics.
// The second to complete fires the echo phase, not round2.
func (rp *RefreshParty) onR1Bcast(otherIds []*tss.PartyID, msgs []*refreshR1Bcast) {
	rp.r1Bcasts = msgs
	if rp.r1JoinCount.Add(1) == 2 {
		rp.startEchoPhase(otherIds)
	}
}

func (rp *RefreshParty) onR1Unicast(otherIds []*tss.PartyID, msgs []*refreshR1Unicast) {
	rp.r1Unicasts = msgs
	if rp.r1JoinCount.Add(1) == 2 {
		rp.startEchoPhase(otherIds)
	}
}

// startEchoPhase: see keygen_party.go.
func (rp *RefreshParty) startEchoPhase(otherIds []*tss.PartyID) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	digests := make(map[string][]byte, len(otherIds))
	for n, pid := range otherIds {
		digests[peerKeyStr(pid)] = commitDigest(echoTagRefresh, pid, rp.r1Bcasts[n].VSSCommitments)
	}

	Pi := rp.params.PartyID()
	out := &echoMsg{Digests: digests}
	m := tss.JsonWrap(refreshTypeEcho, out, Pi, nil)
	if err := rp.params.Broker().Receive(m); err != nil {
		sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("broker echo broadcast: %w", err))
		return
	}
	rcv := tss.NewJsonExpect[echoMsg](refreshTypeEcho, otherIds, rp.onEcho)
	rp.params.Broker().Connect(refreshTypeEcho, rcv)
}

// onEcho: see keygen_party.go.
func (rp *RefreshParty) onEcho(otherIds []*tss.PartyID, msgs []*echoMsg) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	Pi := rp.params.PartyID()
	selfKey := peerKeyStr(Pi)

	myDigests := make(map[string][]byte, len(otherIds)+1)
	myDigests[selfKey] = commitDigest(echoTagRefresh, Pi, flattenPointXY(rp.vsSelf))
	for n, pid := range otherIds {
		myDigests[peerKeyStr(pid)] = commitDigest(echoTagRefresh, pid, rp.r1Bcasts[n].VSSCommitments)
	}

	all := append([]*tss.PartyID{Pi}, otherIds...)
	if err := verifyEchoes(myDigests, selfKey, otherIds, msgs, all, echoSourceRefresh); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	rp.r1Echoes = msgs
	rp.round2(otherIds)
}

func (rp *RefreshParty) round2(otherIds []*tss.PartyID) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	q := ec.Params().N
	threshold := rp.old.T
	bcasts := rp.r1Bcasts
	ucs := rp.r1Unicasts

	for n, pid := range otherIds {
		bc := bcasts[n]
		uc := ucs[n]
		if len(bc.VSSCommitments) != 2*threshold {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s sent %d Vs coords, expected %d",
				pid, len(bc.VSSCommitments), 2*threshold))
			return
		}
		vsj, err := unflattenPointXY(ec, bc.VSSCommitments)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s Vs decode: %w", pid, err))
			return
		}
		shareInt := new(big.Int).SetBytes(uc.Share)
		// Reject non-canonical (>= q) shares — see keygen_party round2
		// for the rationale (echo-bypass via non-canonical bytes).
		if shareInt.Sign() < 0 || shareInt.Cmp(q) >= 0 {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s sent non-canonical refresh-share (>= q)", pid))
			return
		}
		if !verifyZeroConstShare(vsj, Pi.KeyInt(), shareInt) {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s refresh-share verification failed", pid))
			return
		}
		Sj, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(uc.OTSenderSX),
			new(big.Int).SetBytes(uc.OTSenderSY))
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s OT-S invalid: %w", pid, err))
			return
		}
		alpha, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(uc.OTSenderPokAX),
			new(big.Int).SetBytes(uc.OTSenderPokAY))
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s OT-PoK-alpha invalid: %w", pid, err))
			return
		}
		pok := &schnorr.ZKProof{Alpha: alpha, T: new(big.Int).SetBytes(uc.OTSenderPokT)}
		sid := pairBaseSid(rp.ssid, pid.KeyInt(), Pi.KeyInt(), Pi.KeyInt())
		sndMsg := &baseot.SenderMsg1{S: Sj, PoK: pok}

		delta := make([]byte, otext.DeltaBytes)
		if _, err := rp.params.Rand().Read(delta); err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("rand: %w", err))
			return
		}
		rcvr, rcvMsg, err := baseot.NewReceiver(sid, otext.Kappa, delta, sndMsg, rp.params.Rand())
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("party %s base-OT receiver: %w", pid, err))
			return
		}
		rp.baseRcv[peerKeyStr(pid)] = rcvr
		rp.myDelta[peerKeyStr(pid)] = delta
		rp.peerVs[peerKeyStr(pid)] = vsj
		rp.peerShares[peerKeyStr(pid)] = shareInt

		r2 := &keygenR2{OTReceiverR: flattenPointXY(rcvMsg.R)}
		m := tss.JsonWrap(refreshTypeR2, r2, Pi, pid)
		if err := rp.params.Broker().Receive(m); err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("broker r2→%s: %w", pid, err))
			return
		}
	}
	rcv := tss.NewJsonExpect[keygenR2](refreshTypeR2, otherIds, rp.finalize)
	rp.params.Broker().Connect(refreshTypeR2, rcv)
}

func (rp *RefreshParty) finalize(otherIds []*tss.PartyID, msgs []*keygenR2) {
	if err := rp.ctx.Err(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, err)
		return
	}
	Pi := rp.params.PartyID()
	ec := rp.params.EC()
	q := ec.Params().N
	parties := rp.params.Parties().IDs()
	n := len(parties)

	// Compute delta_j = Σ_i f_i(id_j). For SELF, delta_self = own
	// evaluation + sum of received peer shares.
	deltaSelf := new(big.Int).Set(rp.myShares[peerKeyStr(Pi)])
	for _, pid := range otherIds {
		deltaSelf.Add(deltaSelf, rp.peerShares[peerKeyStr(pid)])
		deltaSelf.Mod(deltaSelf, q)
	}
	newXi := new(big.Int).Add(rp.old.Xi, deltaSelf)
	newXi.Mod(newXi, q)

	// New BigXj for each party j: oldBigXj[j] + delta_j · G, where
	// delta_j = Σ_i f_i(id_j) = local-eval + sum-of-peer-evals-at-id_j.
	// We have local-evals in rp.myShares; we need each peer's
	// f_peer(id_j) which we DON'T have (the peer only sent its share
	// for our id, not the full table). So instead we compute via the
	// commitments: each peer's polynomial evaluated at id_j · G is
	// Σ_k id_j^k · V_{peer, k}. Summed over peers + own gives the
	// total delta_j · G.
	newBigXj := make([]*crypto.ECPoint, n)
	for _, pj := range parties {
		// Compute delta_j · G via commitments.
		deltaG, err := evalCommitmentSumZeroConst(rp.vsSelf, rp.peerVs, pj.KeyInt())
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("delta·G[%d]: %w", pj.Index, err))
			return
		}
		newPoint, err := rp.old.BigXj[pj.Index].Add(deltaG)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("new BigXj[%d]: %w", pj.Index, err))
			return
		}
		newBigXj[pj.Index] = newPoint
	}

	// Sanity: newXi · G == newBigXj[Pi.Index].
	expect := crypto.ScalarBaseMult(ec, newXi)
	if !expect.Equals(newBigXj[Pi.Index]) {
		sendOnce(&rp.errOnce, rp.Err, errors.New("refresh consistency check failed: newXi·G != newBigXj[self]"))
		return
	}

	// Assemble OT extension state for every pair.
	ot := make([]*PairOTState, n)
	for _, pj := range otherIds {
		peerk := peerKeyStr(pj)
		chosen, err := rp.baseRcv[peerk].Finalize()
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("base-OT receiver finalize for %s: %w", pj, err))
			return
		}
		extSender, err := otext.NewExtSenderFromBase(rp.myDelta[peerk], chosen)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("ExtSender for %s: %w", pj, err))
			return
		}
		var r2 *keygenR2
		for idx, pid := range otherIds {
			if pid.KeyInt().Cmp(pj.KeyInt()) == 0 {
				r2 = msgs[idx]
				break
			}
		}
		if r2 == nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("missing r2 from %s", pj))
			return
		}
		rPoints, err := unflattenPointXY(ec, r2.OTReceiverR)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("decode R from %s: %w", pj, err))
			return
		}
		k0, k1, err := rp.baseSnd[peerk].Finalize(&baseot.ReceiverMsg1{R: rPoints})
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("base-OT sender finalize for %s: %w", pj, err))
			return
		}
		extReceiver, err := otext.NewExtReceiverFromBase(k0, k1)
		if err != nil {
			sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("ExtReceiver for %s: %w", pj, err))
			return
		}
		ot[pj.Index] = &PairOTState{AsAlice: extReceiver, AsBob: extSender}
	}

	newKey := &Key{
		Curve:     ec,
		N:         rp.old.N,
		T:         rp.old.T,
		Idx:       rp.old.Idx,
		PartyIDs:  rp.old.PartyIDs,
		Xi:        newXi,
		BigXj:     newBigXj,
		ECDSAPub:  rp.old.ECDSAPub,
		OT:        ot,
		ChainCode: append([]byte(nil), rp.old.ChainCode...),
	}
	if err := newKey.ValidateBasic(); err != nil {
		sendOnce(&rp.errOnce, rp.Err, fmt.Errorf("refresh finalize ValidateBasic: %w", err))
		return
	}
	sendOnce(&rp.doneOnce, rp.Done, newKey)
}

// evalCommitmentSumZeroConst computes Σ_i (f_i(id_j) · G) where each
// f_i has zero constant term, given the local Vs and each peer's Vs.
// The curve is inferred from the first point.
//
// Returns an error if any point arithmetic fails. Previously this
// function silently swallowed Add errors (`if err == nil { acc = sum }`)
// which let a peer with malformed commitments shift another party's
// BigXj into an unrelated value — the self-consistency check at the
// caller's `Pi.Index` slot would still pass but the j ≠ self slots
// could end up off-protocol. Propagating the error surfaces the
// problem immediately rather than producing a key with bad public
// commitments.
func evalCommitmentSumZeroConst(vsSelf []*crypto.ECPoint, peerVs map[string][]*crypto.ECPoint, id *big.Int) (*crypto.ECPoint, error) {
	if len(vsSelf) == 0 {
		return nil, errors.New("dklstss: evalCommitmentSumZeroConst empty vsSelf")
	}
	curve := vsSelf[0].Curve()
	q := curve.Params().N

	eval := func(Vs []*crypto.ECPoint) (*crypto.ECPoint, error) {
		idPow := new(big.Int).Mod(id, q)
		if idPow.Sign() == 0 {
			return nil, errors.New("id ≡ 0 mod q (invalid party identifier)")
		}
		var acc *crypto.ECPoint
		for k, V := range Vs {
			if !V.ValidateBasic() {
				// Defense-in-depth: ECPoint.ScalarMult panics on input
				// points whose internal state is malformed (nil coords,
				// off-curve). Honest peers' commitments come from
				// unflattenPointXY which uses NewECPoint and guards
				// against this; the explicit reject here makes the
				// contract local and survives future refactors.
				return nil, fmt.Errorf("Vs[%d] is not a valid curve point", k)
			}
			term := V.ScalarMult(idPow)
			if acc == nil {
				acc = term
			} else {
				sum, err := acc.Add(term)
				if err != nil {
					return nil, fmt.Errorf("Vs[%d] addition: %w", k, err)
				}
				acc = sum
			}
			idPow = new(big.Int).Mul(idPow, id)
			idPow.Mod(idPow, q)
		}
		return acc, nil
	}

	out, err := eval(vsSelf)
	if err != nil {
		return nil, fmt.Errorf("vsSelf: %w", err)
	}
	for peerKey, vs := range peerVs {
		add, err := eval(vs)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", peerKey, err)
		}
		if add == nil {
			continue
		}
		if out == nil {
			out = add
			continue
		}
		sum, err := out.Add(add)
		if err != nil {
			return nil, fmt.Errorf("aggregate (peer %s): %w", peerKey, err)
		}
		out = sum
	}
	return out, nil
}

// refreshR1Bcast is the round-1 BROADCAST: Vs commitments to the
// zero-constant polynomial. Same bytes for every peer; sent via a
// To==nil broadcast as the H-3 equivocation defense.
type refreshR1Bcast struct {
	VSSCommitments [][]byte `json:"vss_commitments"`
}

// refreshR1Unicast is the round-1 UNICAST half: per-recipient share +
// this dealer's base-OT-Sender first-round message.
type refreshR1Unicast struct {
	Share         []byte `json:"share"`
	OTSenderSX    []byte `json:"ot_sender_s_x"`
	OTSenderSY    []byte `json:"ot_sender_s_y"`
	OTSenderPokAX []byte `json:"ot_sender_pok_alpha_x"`
	OTSenderPokAY []byte `json:"ot_sender_pok_alpha_y"`
	OTSenderPokT  []byte `json:"ot_sender_pok_t"`
}

const (
	refreshTypeR1Bcast   = "dkls:refresh:r1bc"
	refreshTypeR1Unicast = "dkls:refresh:r1uc"
	refreshTypeEcho      = "dkls:refresh:echo"
	refreshTypeR2        = "dkls:refresh:r2"

	echoTagRefresh    = "DKLS23-echo-refresh-v1"
	echoSourceRefresh = "dklstss-refresh"
)

func refreshSession(params *tss.Parameters, key *Key) []byte {
	// Bound to (pub, party set). The base-OT setup that follows each
	// refresh uses pairBaseSid(ssid, ...) for the per-pair sids; even if
	// two refreshes produce the same ssid (same key + parties), the base
	// OT messages are randomized internally (fresh y, delta, x_i per
	// call) and the derived OT-extension seeds are independent across
	// refreshes — so sid collision here does not break security. Refresh
	// also does NOT run signing-time ΠMul, so the per-call PRG sid
	// binding in crypto/ot/otext is not exercised at refresh time.
	h := sha256.New()
	h.Write([]byte("DKLS23-refresh-party-v1-"))
	h.Write(key.ECDSAPub.X().Bytes())
	h.Write(key.ECDSAPub.Y().Bytes())
	for _, p := range params.Parties().IDs() {
		h.Write(p.KeyInt().Bytes())
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}
