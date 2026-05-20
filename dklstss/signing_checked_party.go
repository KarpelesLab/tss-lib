// Copyright © 2026 KarpelesLab.

package dklstss

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/ole"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// CheckedSigningParty is the broker-driven analog of the synchronous
// SignChecked: it runs the same three-round DKLs23 signing flow as
// SigningParty but invokes the Mul-then-check primitives
// (ole.CheckedAliceStep1 / ole.CheckedBobStep1 / ole.CheckedAliceStep2)
// so that a malicious Bob who uses inconsistent β across the two
// parallel ΠMul instances is caught with identifiable abort. The
// failing party's PartyID is surfaced in tss.Error.Culprits().
//
// Cost: roughly 2× the wire traffic and CPU of SigningParty (two
// parallel ΠMul flows per pair instead of one).
//
// Lifecycle mirrors SigningParty (see signing_party.go for inline
// rationale of each step). The wire-level differences are:
//
//   - Round 2 (Alice envelope): two extension messages per pair, one
//     per parallel ΠMul instance (sub-sid "|1" and "|2").
//   - Round 3 (Bob response): per pair, two correction slices plus
//     Bob's cross-run consistency value Z = u_B1 − u_B2.
//   - Round 4 (Alice second step): verifies Z_A + Z_B == 0 mod q. On
//     failure, returns ErrMulCheckFailed wrapped in a tss.Error with
//     the offending Bob in Culprits().
//
// The K_i echo-broadcast phase (signing_party.go round2KCollect /
// round2Echo) is replicated here so the broker-equivocation defense
// from the prior commit applies to CheckedSigningParty as well.
type CheckedSigningParty struct {
	ctx    context.Context
	params *tss.Parameters
	key    *Key
	hash   []byte
	tweak  *big.Int
	ssid   []byte

	subset        tss.SortedPartyIDs
	myPos         int
	otherSubset   []*tss.PartyID
	subsetIDs     []*big.Int
	lambdas       []*big.Int
	sxBySubsetIdx []*big.Int

	k_i   *big.Int
	rho_i *big.Int
	K_i   *crypto.ECPoint
	r     *big.Int

	// Alice-side state: per peer × per ΠMul-kind. The Checked variant
	// holds a *ole.CheckedAliceState rather than the plain AliceState.
	aliceStateK map[string]*ole.CheckedAliceState
	aliceStateX map[string]*ole.CheckedAliceState

	peerK map[string]*crypto.ECPoint

	kRhoShare []*big.Int
	xRhoShare []*big.Int

	phi_i  *big.Int
	shat_i *big.Int

	r4msgs map[string]*signR4

	Done chan *Signature
	Err  chan error

	doneOnce sync.Once
	errOnce  sync.Once
}

// NewCheckedSigning kicks off broker-driven Mul-then-check signing for
// the local party. Same input contract as NewSigning; the result is
// delivered on Done (or Err) just like SigningParty.
func NewCheckedSigning(ctx context.Context, params *tss.Parameters, key *Key, hash []byte, subset tss.SortedPartyIDs, tweak *big.Int) (*CheckedSigningParty, error) {
	if ctx == nil || params == nil || key == nil {
		return nil, errors.New("dklstss: NewCheckedSigning nil argument")
	}
	if len(hash) == 0 {
		return nil, errors.New("dklstss: NewCheckedSigning empty hash")
	}
	if err := key.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("dklstss: NewCheckedSigning invalid key: %w", err)
	}
	if !tss.SameCurve(params.EC(), tss.S256()) {
		return nil, errors.New("dklstss: NewCheckedSigning requires secp256k1")
	}
	t1 := key.T + 1
	if len(subset) != t1 {
		return nil, fmt.Errorf("dklstss: NewCheckedSigning subset must have %d parties, got %d", t1, len(subset))
	}
	if err := validateSortedSubset(subset); err != nil {
		return nil, fmt.Errorf("dklstss: NewCheckedSigning: %w", err)
	}

	myPID := params.PartyID()
	myPos := -1
	for i, p := range subset {
		if p.KeyInt().Cmp(myPID.KeyInt()) == 0 {
			myPos = i
			break
		}
	}
	if myPos < 0 {
		return nil, errors.New("dklstss: NewCheckedSigning self not in subset")
	}

	ec := params.EC()
	q := ec.Params().N

	subsetIDs := make([]*big.Int, t1)
	for i, p := range subset {
		subsetIDs[i] = p.KeyInt()
	}
	lambdas := make([]*big.Int, t1)
	for i := 0; i < t1; i++ {
		lam, err := lagrangeCoefficient(q, subsetIDs, i)
		if err != nil {
			return nil, fmt.Errorf("dklstss: NewCheckedSigning lagrange: %w", err)
		}
		lambdas[i] = lam
	}
	// sx_i = λ_i · Xi mod q for self; nil placeholder for others.
	sxBySubsetIdx := make([]*big.Int, t1)
	sxBySubsetIdx[myPos] = new(big.Int).Mod(new(big.Int).Mul(lambdas[myPos], key.Xi), q)
	if tweak != nil && myPos == 0 {
		sxBySubsetIdx[0] = new(big.Int).Mod(new(big.Int).Add(sxBySubsetIdx[0], tweak), q)
	}

	otherSubset := make([]*tss.PartyID, 0, t1-1)
	for i, p := range subset {
		if i == myPos {
			continue
		}
		otherSubset = append(otherSubset, p)
	}

	sp := &CheckedSigningParty{
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
		aliceStateK:   make(map[string]*ole.CheckedAliceState, t1-1),
		aliceStateX:   make(map[string]*ole.CheckedAliceState, t1-1),
		peerK:         make(map[string]*crypto.ECPoint, t1-1),
		kRhoShare:     make([]*big.Int, t1),
		xRhoShare:     make([]*big.Int, t1),
		r4msgs:        make(map[string]*signR4, t1),
		Done:          make(chan *Signature, 1),
		Err:           make(chan error, 1),
	}

	if err := sp.round1(); err != nil {
		return nil, fmt.Errorf("dklstss: NewCheckedSigning round1: %w", err)
	}
	return sp, nil
}

func (sp *CheckedSigningParty) indexInFullCommittee(p *tss.PartyID) int {
	for i, q := range sp.key.PartyIDs {
		if q.KeyInt().Cmp(p.KeyInt()) == 0 {
			return i
		}
	}
	return -1
}

func (sp *CheckedSigningParty) round1() error {
	if err := sp.ctx.Err(); err != nil {
		return err
	}
	Pi := sp.params.PartyID()
	ec := sp.params.EC()
	q := ec.Params().N

	sp.k_i = common.GetRandomPositiveInt(sp.params.Rand(), q)
	sp.rho_i = common.GetRandomPositiveInt(sp.params.Rand(), q)
	sp.K_i = ctmul.ScalarBaseMultWithRand(ec, sp.k_i, sp.params.Rand())

	zero := new(big.Int)
	sp.kRhoShare[sp.myPos] = crypto.CTScalarMulAddModN(ec, sp.k_i, sp.rho_i, zero)
	sp.xRhoShare[sp.myPos] = crypto.CTScalarMulAddModN(ec, sp.sxBySubsetIdx[sp.myPos], sp.rho_i, zero)

	r1 := &signR1{KiX: sp.K_i.X().Bytes(), KiY: sp.K_i.Y().Bytes()}
	bcast := tss.JsonWrap(checkedSignTypeR1, r1, Pi, nil)
	if err := sp.params.Broker().Receive(bcast); err != nil {
		return fmt.Errorf("broker r1 bcast: %w", err)
	}
	rcv := tss.NewJsonExpect[signR1](checkedSignTypeR1, sp.otherSubset, sp.round2KCollect)
	sp.params.Broker().Connect(checkedSignTypeR1, rcv)
	return nil
}

func (sp *CheckedSigningParty) round2KCollect(otherIds []*tss.PartyID, msgs []*signR1) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	ec := sp.params.EC()
	q := ec.Params().N
	Pi := sp.params.PartyID()

	R := sp.K_i
	for n, pid := range otherIds {
		Kj, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(msgs[n].KiX),
			new(big.Int).SetBytes(msgs[n].KiY))
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s sent invalid K_j: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
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
		sendOnce(&sp.errOnce, sp.Err, errors.New("R.X mod q == 0, retry"))
		return
	}
	sp.r = r

	digests := make(map[string][]byte, len(otherIds))
	for _, pid := range otherIds {
		digests[peerKeyStr(pid)] = kIDigest(pid, sp.peerK[peerKeyStr(pid)])
	}
	echoOut := &echoMsg{Digests: digests}
	echoBcast := tss.JsonWrap(checkedSignTypeR1Echo, echoOut, Pi, nil)
	if err := sp.params.Broker().Receive(echoBcast); err != nil {
		sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r1echo: %w", err))
		return
	}
	rcv := tss.NewJsonExpect[echoMsg](checkedSignTypeR1Echo, sp.otherSubset,
		func(ids []*tss.PartyID, msgs []*echoMsg) {
			sp.round2Echo(otherIds, ids, msgs)
		})
	sp.params.Broker().Connect(checkedSignTypeR1Echo, rcv)
}

func (sp *CheckedSigningParty) round2Echo(otherIds, echoers []*tss.PartyID, msgs []*echoMsg) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	Pi := sp.params.PartyID()

	myDigests := make(map[string][]byte, len(otherIds)+1)
	for _, pid := range otherIds {
		myDigests[peerKeyStr(pid)] = kIDigest(pid, sp.peerK[peerKeyStr(pid)])
	}
	selfKey := peerKeyStr(Pi)
	myDigests[selfKey] = kIDigest(Pi, sp.K_i)
	all := append([]*tss.PartyID{Pi}, otherIds...)
	if err := verifyEchoes(myDigests, selfKey, echoers, msgs, all, echoSourceCheckedSign); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}

	sp.ssid = mixRoundOneSsid(sp.ssid, Pi, sp.K_i, otherIds, sp.peerK)

	for _, Pj := range sp.otherSubset {
		alicePair := sp.key.OT[sp.indexInFullCommittee(Pj)]
		if alicePair == nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("missing OT state with peer %s", Pj))
			return
		}
		sidK := signMulSid(sp.ssid, "checked-kxrho", Pi.KeyInt(), Pj.KeyInt())
		sidX := signMulSid(sp.ssid, "checked-xxrho", Pi.KeyInt(), Pj.KeyInt())

		// Mul-then-check: each kind launches TWO parallel ΠMul instances.
		msgK1, msgK2, stK, err := ole.CheckedAliceStep1(sidK, alicePair.AsAlice, sp.k_i)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("ΠMul-k Checked-Alice1 to %s: %w", Pj, err))
			return
		}
		msgX1, msgX2, stX, err := ole.CheckedAliceStep1(sidX, alicePair.AsAlice, sp.sxBySubsetIdx[sp.myPos])
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("ΠMul-x Checked-Alice1 to %s: %w", Pj, err))
			return
		}
		sp.aliceStateK[peerKeyStr(Pj)] = stK
		sp.aliceStateX[peerKeyStr(Pj)] = stX

		r2 := &checkedSignR2{
			AliceK1: encodeExtendMsg(msgK1),
			AliceK2: encodeExtendMsg(msgK2),
			AliceX1: encodeExtendMsg(msgX1),
			AliceX2: encodeExtendMsg(msgX2),
		}
		m := tss.JsonWrap(checkedSignTypeR2, r2, Pi, Pj)
		if err := sp.params.Broker().Receive(m); err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r2→%s: %w", Pj, err))
			return
		}
	}

	rcv := tss.NewJsonExpect[checkedSignR2](checkedSignTypeR2, sp.otherSubset, sp.round3)
	sp.params.Broker().Connect(checkedSignTypeR2, rcv)
}

func (sp *CheckedSigningParty) round3(otherIds []*tss.PartyID, msgs []*checkedSignR2) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	Pi := sp.params.PartyID()
	ec := sp.params.EC()

	for n, pid := range otherIds {
		bobPair := sp.key.OT[sp.indexInFullCommittee(pid)]
		if bobPair == nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("missing OT state with peer %s", pid))
			return
		}
		mK1, err := decodeExtendMsg(msgs[n].AliceK1)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s AliceK1 decode: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		mK2, err := decodeExtendMsg(msgs[n].AliceK2)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s AliceK2 decode: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		mX1, err := decodeExtendMsg(msgs[n].AliceX1)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s AliceX1 decode: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		mX2, err := decodeExtendMsg(msgs[n].AliceX2)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s AliceX2 decode: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		sidK := signMulSid(sp.ssid, "checked-kxrho", pid.KeyInt(), Pi.KeyInt())
		sidX := signMulSid(sp.ssid, "checked-xxrho", pid.KeyInt(), Pi.KeyInt())

		bobMsgK, uBK, err := ole.CheckedBobStep1(sidK, bobPair.AsBob, sp.rho_i, mK1, mK2)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("CheckedBob-k from %s: %w", pid, err))
			return
		}
		bobMsgX, uBX, err := ole.CheckedBobStep1(sidX, bobPair.AsBob, sp.rho_i, mX1, mX2)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("CheckedBob-x from %s: %w", pid, err))
			return
		}
		// Find Bob's position in subset (which equals self's myPos in
		// this iteration since we ARE Bob here).
		sp.kRhoShare[sp.myPos] = addMod(ec.Params().N, sp.kRhoShare[sp.myPos], uBK)
		sp.xRhoShare[sp.myPos] = addMod(ec.Params().N, sp.xRhoShare[sp.myPos], uBX)

		r3 := &checkedSignR3{
			BobK1: encodeBobMsg(bobMsgK.Msg1),
			BobK2: encodeBobMsg(bobMsgK.Msg2),
			BobKZ: bobMsgK.Z.Bytes(),
			BobX1: encodeBobMsg(bobMsgX.Msg1),
			BobX2: encodeBobMsg(bobMsgX.Msg2),
			BobXZ: bobMsgX.Z.Bytes(),
		}
		m := tss.JsonWrap(checkedSignTypeR3, r3, Pi, pid)
		if err := sp.params.Broker().Receive(m); err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r3→%s: %w", pid, err))
			return
		}
	}

	rcv := tss.NewJsonExpect[checkedSignR3](checkedSignTypeR3, sp.otherSubset, sp.round4)
	sp.params.Broker().Connect(checkedSignTypeR3, rcv)
}

func (sp *CheckedSigningParty) round4(otherIds []*tss.PartyID, msgs []*checkedSignR3) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	ec := sp.params.EC()
	q := ec.Params().N
	Pi := sp.params.PartyID()

	for n, pid := range otherIds {
		stK := sp.aliceStateK[peerKeyStr(pid)]
		stX := sp.aliceStateX[peerKeyStr(pid)]
		if stK == nil || stX == nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("missing Alice state for %s", pid))
			return
		}
		bobMsgK1, err := decodeBobMsg(msgs[n].BobK1)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s BobK1 decode: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		bobMsgK2, err := decodeBobMsg(msgs[n].BobK2)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s BobK2 decode: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		bobMsgX1, err := decodeBobMsg(msgs[n].BobX1)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s BobX1 decode: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		bobMsgX2, err := decodeBobMsg(msgs[n].BobX2)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s BobX2 decode: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		bobZK := new(big.Int).SetBytes(msgs[n].BobKZ)
		bobZX := new(big.Int).SetBytes(msgs[n].BobXZ)
		// Range-check Z mod q.
		if bobZK.Cmp(q) >= 0 || bobZX.Cmp(q) >= 0 {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("party %s sent non-canonical Z (>= q)", pid),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}

		uAK, err := ole.CheckedAliceStep2(stK, &ole.CheckedBobMsg{Msg1: bobMsgK1, Msg2: bobMsgK2, Z: bobZK})
		if err != nil {
			// Mul-then-check failure → attribute to Bob (this peer).
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("Mul-then-check failed for k·ρ with %s: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		uAX, err := ole.CheckedAliceStep2(stX, &ole.CheckedBobMsg{Msg1: bobMsgX1, Msg2: bobMsgX2, Z: bobZX})
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, error(tss.NewError(
				fmt.Errorf("Mul-then-check failed for sx·ρ with %s: %w", pid, err),
				echoSourceCheckedSign, 0, nil, pid)))
			return
		}
		sp.kRhoShare[sp.myPos] = addMod(q, sp.kRhoShare[sp.myPos], uAK)
		sp.xRhoShare[sp.myPos] = addMod(q, sp.xRhoShare[sp.myPos], uAX)
	}

	// Compute (φ_i, ŝ_i). h = hashToScalar(q, hash).
	h := hashToScalar(q, sp.hash)
	sp.phi_i = sp.kRhoShare[sp.myPos]
	sp.shat_i = crypto.CTScalarMulAddModN(ec, sp.rho_i, h, zeroBig)
	sp.shat_i = crypto.CTScalarMulAddModN(ec, sp.r, sp.xRhoShare[sp.myPos], sp.shat_i)

	for _, Pj := range sp.otherSubset {
		r4 := &signR4{Phi: sp.phi_i.Bytes(), Shat: sp.shat_i.Bytes()}
		m := tss.JsonWrap(checkedSignTypeR4, r4, Pi, Pj)
		if err := sp.params.Broker().Receive(m); err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("broker r4→%s: %w", Pj, err))
			return
		}
	}

	rcv := tss.NewJsonExpect[signR4](checkedSignTypeR4, sp.otherSubset, sp.finalize)
	sp.params.Broker().Connect(checkedSignTypeR4, rcv)
}

func (sp *CheckedSigningParty) finalize(otherIds []*tss.PartyID, msgs []*signR4) {
	if err := sp.ctx.Err(); err != nil {
		sendOnce(&sp.errOnce, sp.Err, err)
		return
	}
	q := sp.params.EC().Params().N

	phi := new(big.Int).Set(sp.phi_i)
	shat := new(big.Int).Set(sp.shat_i)
	for n, pid := range otherIds {
		_ = pid
		pj := new(big.Int).SetBytes(msgs[n].Phi)
		sj := new(big.Int).SetBytes(msgs[n].Shat)
		phi = addMod(q, phi, pj)
		shat = addMod(q, shat, sj)
	}
	if phi.Sign() == 0 {
		sendOnce(&sp.errOnce, sp.Err, errors.New("aggregate φ == 0"))
		return
	}
	phiInv := common.ModInt(q).ModInverse(phi)
	if phiInv == nil {
		sendOnce(&sp.errOnce, sp.Err, errors.New("aggregate φ has no inverse"))
		return
	}
	s := new(big.Int).Mod(new(big.Int).Mul(shat, phiInv), q)
	if s.Sign() == 0 {
		sendOnce(&sp.errOnce, sp.Err, errors.New("s == 0"))
		return
	}
	// Reconstruct R for v parity.
	R := sp.K_i
	for _, pid := range sp.otherSubset {
		Kj := sp.peerK[peerKeyStr(pid)]
		Radd, err := R.Add(Kj)
		if err != nil {
			sendOnce(&sp.errOnce, sp.Err, fmt.Errorf("R re-aggregation: %w", err))
			return
		}
		R = Radd
	}
	v := byte(R.Y().Bit(0))
	halfQ := new(big.Int).Rsh(q, 1)
	if s.Cmp(halfQ) > 0 {
		s = new(big.Int).Sub(q, s)
		v ^= 1
	}

	sig := &Signature{R: sp.r, S: s, V: v}
	sendOnce(&sp.doneOnce, sp.Done, sig)
}

// --- wire types -----------------------------------------------------

type checkedSignR2 struct {
	AliceK1 *encodedExtendMsg `json:"alice_k1"`
	AliceK2 *encodedExtendMsg `json:"alice_k2"`
	AliceX1 *encodedExtendMsg `json:"alice_x1"`
	AliceX2 *encodedExtendMsg `json:"alice_x2"`
}

type checkedSignR3 struct {
	BobK1 [][]byte `json:"bob_k1"`
	BobK2 [][]byte `json:"bob_k2"`
	BobKZ []byte   `json:"bob_kz"`
	BobX1 [][]byte `json:"bob_x1"`
	BobX2 [][]byte `json:"bob_x2"`
	BobXZ []byte   `json:"bob_xz"`
}

const (
	checkedSignTypeR1     = "dkls:csign:r1"
	checkedSignTypeR1Echo = "dkls:csign:r1echo"
	checkedSignTypeR2     = "dkls:csign:r2"
	checkedSignTypeR3     = "dkls:csign:r3"
	checkedSignTypeR4     = "dkls:csign:r4"

	echoSourceCheckedSign = "dklstss-csign"
)

var zeroBig = new(big.Int)
