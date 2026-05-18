package dklstss

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/ole"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// PresignParty is the broker-driven offline pre-signing protocol.
// Rounds 1-3 mirror SigningParty (K_i broadcast, ΠMul Alice envelopes,
// ΠMul Bob responses); the result is a *PresignOutput delivered on
// Done. Subsequent SignWithPresign / SignWithPresignDurable consumes
// the output in a single online round.
//
// The PresignOutput emitted here is suitable for SignWithPresign by
// the SAME party that ran the presign. Cross-party single-use is
// enforced by the atomic CAS inside PresignOutput; durable single-use
// across crash-restart requires the caller's UsedPresignStore.
type PresignParty struct {
	ctx    context.Context
	params *tss.Parameters
	key    *Key
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
	R     *crypto.ECPoint

	aliceStateK map[string]*ole.AliceState
	aliceStateX map[string]*ole.AliceState
	peerK       map[string]*crypto.ECPoint

	kRhoShare []*big.Int
	xRhoShare []*big.Int

	Done chan *PresignOutput
	Err  chan error
}

// NewPresign kicks off broker-driven pre-signing.
func NewPresign(ctx context.Context, params *tss.Parameters, key *Key, subset tss.SortedPartyIDs) (*PresignParty, error) {
	if ctx == nil || params == nil || key == nil {
		return nil, errors.New("dklstss: NewPresign nil argument")
	}
	if err := key.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("dklstss: NewPresign invalid key: %w", err)
	}
	if !tss.SameCurve(params.EC(), tss.S256()) {
		return nil, errors.New("dklstss: NewPresign requires secp256k1")
	}
	if len(subset) != key.T+1 {
		return nil, fmt.Errorf("dklstss: NewPresign subset size %d, expected T+1=%d", len(subset), key.T+1)
	}
	if err := validateSortedSubset(subset); err != nil {
		return nil, fmt.Errorf("dklstss: NewPresign %w", err)
	}
	self := params.PartyID()
	myPos := -1
	for i, p := range subset {
		if p.KeyInt().Cmp(self.KeyInt()) == 0 {
			myPos = i
			break
		}
	}
	if myPos < 0 {
		return nil, errors.New("dklstss: NewPresign self not in subset")
	}
	q := params.EC().Params().N

	subsetIDs := make([]*big.Int, len(subset))
	for i, p := range subset {
		subsetIDs[i] = p.KeyInt()
	}
	lambdas := make([]*big.Int, len(subset))
	for i := range subset {
		lam, err := lagrangeCoefficient(q, subsetIDs, i)
		if err != nil {
			return nil, fmt.Errorf("dklstss: NewPresign lagrange: %w", err)
		}
		lambdas[i] = lam
	}
	sx := make([]*big.Int, len(subset))
	sx[myPos] = new(big.Int).Mul(lambdas[myPos], key.Xi)
	sx[myPos].Mod(sx[myPos], q)

	otherSubset := make([]*tss.PartyID, 0, len(subset)-1)
	for _, p := range subset {
		if p.KeyInt().Cmp(self.KeyInt()) != 0 {
			otherSubset = append(otherSubset, p)
		}
	}

	pp := &PresignParty{
		ctx:           ctx,
		params:        params,
		key:           key,
		ssid:          presignSession(params, key, subset),
		subset:        subset,
		myPos:         myPos,
		otherSubset:   otherSubset,
		subsetIDs:     subsetIDs,
		lambdas:       lambdas,
		sxBySubsetIdx: sx,
		aliceStateK:   make(map[string]*ole.AliceState),
		aliceStateX:   make(map[string]*ole.AliceState),
		peerK:         make(map[string]*crypto.ECPoint),
		kRhoShare:     make([]*big.Int, len(subset)),
		xRhoShare:     make([]*big.Int, len(subset)),
		Done:          make(chan *PresignOutput, 1),
		Err:           make(chan error, 1),
	}
	for i := range pp.kRhoShare {
		pp.kRhoShare[i] = new(big.Int)
		pp.xRhoShare[i] = new(big.Int)
	}
	if err := pp.round1(); err != nil {
		return nil, fmt.Errorf("dklstss: NewPresign round1: %w", err)
	}
	return pp, nil
}

func (pp *PresignParty) round1() error {
	Pi := pp.params.PartyID()
	ec := pp.params.EC()
	q := ec.Params().N

	pp.k_i = common.GetRandomPositiveInt(pp.params.Rand(), q)
	pp.rho_i = common.GetRandomPositiveInt(pp.params.Rand(), q)
	pp.K_i = ctmul.ScalarBaseMultWithRand(ec, pp.k_i, pp.params.Rand())

	pp.kRhoShare[pp.myPos] = new(big.Int).Mul(pp.k_i, pp.rho_i)
	pp.kRhoShare[pp.myPos].Mod(pp.kRhoShare[pp.myPos], q)
	pp.xRhoShare[pp.myPos] = new(big.Int).Mul(pp.sxBySubsetIdx[pp.myPos], pp.rho_i)
	pp.xRhoShare[pp.myPos].Mod(pp.xRhoShare[pp.myPos], q)

	r1 := &signR1{KiX: pp.K_i.X().Bytes(), KiY: pp.K_i.Y().Bytes()}
	for _, Pj := range pp.otherSubset {
		m := tss.JsonWrap(presignTypeR1, r1, Pi, Pj)
		if err := pp.params.Broker().Receive(m); err != nil {
			return fmt.Errorf("broker r1→%s: %w", Pj, err)
		}
	}
	rcv := tss.NewJsonExpect[signR1](presignTypeR1, pp.otherSubset, pp.round2)
	pp.params.Broker().Connect(presignTypeR1, rcv)
	return nil
}

func (pp *PresignParty) round2(otherIds []*tss.PartyID, msgs []*signR1) {
	if err := pp.ctx.Err(); err != nil {
		pp.Err <- err
		return
	}
	ec := pp.params.EC()
	q := ec.Params().N
	Pi := pp.params.PartyID()

	R := pp.K_i
	for n, pid := range otherIds {
		Kj, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(msgs[n].KiX),
			new(big.Int).SetBytes(msgs[n].KiY))
		if err != nil {
			pp.Err <- fmt.Errorf("party %s sent invalid K_j: %w", pid, err)
			return
		}
		pp.peerK[peerKeyStr(pid)] = Kj
		Radd, err := R.Add(Kj)
		if err != nil {
			pp.Err <- fmt.Errorf("R aggregation: %w", err)
			return
		}
		R = Radd
	}
	pp.R = R
	r := new(big.Int).Mod(R.X(), q)
	if r.Sign() == 0 {
		pp.Err <- errors.New("R.X mod q == 0, retry")
		return
	}
	pp.r = r

	// Mix every signer's K_i into the effective ssid so the OT-extension
	// sid varies per presign call — required to keep the per-call PRG
	// derivation in crypto/ot/otext distinct across reuses of the same
	// long-term OT-extension setup. presignSession alone binds only to
	// (pub, subset) which is constant across many presigns.
	pp.ssid = mixRoundOneSsid(pp.ssid, Pi, pp.K_i, pp.otherSubset, pp.peerK)

	for _, Pj := range pp.otherSubset {
		alicePair := pp.key.OT[pp.indexInFullCommittee(Pj)]
		if alicePair == nil {
			pp.Err <- fmt.Errorf("missing OT state with peer %s", Pj)
			return
		}
		sidK := signMulSid(pp.ssid, "presign-kxrho", Pi.KeyInt(), Pj.KeyInt())
		sidX := signMulSid(pp.ssid, "presign-xxrho", Pi.KeyInt(), Pj.KeyInt())

		msgK, stK, err := ole.AliceStep1(sidK, alicePair.AsAlice, pp.k_i)
		if err != nil {
			pp.Err <- fmt.Errorf("ΠMul-k Alice1 to %s: %w", Pj, err)
			return
		}
		msgX, stX, err := ole.AliceStep1(sidX, alicePair.AsAlice, pp.sxBySubsetIdx[pp.myPos])
		if err != nil {
			pp.Err <- fmt.Errorf("ΠMul-x Alice1 to %s: %w", Pj, err)
			return
		}
		pp.aliceStateK[peerKeyStr(Pj)] = stK
		pp.aliceStateX[peerKeyStr(Pj)] = stX

		r2 := &signR2{AliceK: encodeExtendMsg(msgK), AliceX: encodeExtendMsg(msgX)}
		m := tss.JsonWrap(presignTypeR2, r2, Pi, Pj)
		if err := pp.params.Broker().Receive(m); err != nil {
			pp.Err <- fmt.Errorf("broker r2→%s: %w", Pj, err)
			return
		}
	}
	rcv := tss.NewJsonExpect[signR2](presignTypeR2, pp.otherSubset, pp.round3)
	pp.params.Broker().Connect(presignTypeR2, rcv)
}

func (pp *PresignParty) round3(otherIds []*tss.PartyID, msgs []*signR2) {
	if err := pp.ctx.Err(); err != nil {
		pp.Err <- err
		return
	}
	Pi := pp.params.PartyID()
	q := pp.params.EC().Params().N

	for n, pid := range otherIds {
		r2 := msgs[n]
		bobPair := pp.key.OT[pp.indexInFullCommittee(pid)]
		if bobPair == nil {
			pp.Err <- fmt.Errorf("missing OT state with peer %s", pid)
			return
		}
		extMsgK, err := decodeExtendMsg(r2.AliceK)
		if err != nil {
			pp.Err <- fmt.Errorf("decode Alice k-envelope from %s: %w", pid, err)
			return
		}
		extMsgX, err := decodeExtendMsg(r2.AliceX)
		if err != nil {
			pp.Err <- fmt.Errorf("decode Alice x-envelope from %s: %w", pid, err)
			return
		}
		sidK := signMulSid(pp.ssid, "presign-kxrho", pid.KeyInt(), Pi.KeyInt())
		sidX := signMulSid(pp.ssid, "presign-xxrho", pid.KeyInt(), Pi.KeyInt())

		bMsgK, uBK, err := ole.BobStep1(sidK, bobPair.AsBob, pp.rho_i, extMsgK)
		if err != nil {
			pp.Err <- fmt.Errorf("ΠMul-k Bob1 with %s: %w", pid, err)
			return
		}
		bMsgX, uBX, err := ole.BobStep1(sidX, bobPair.AsBob, pp.rho_i, extMsgX)
		if err != nil {
			pp.Err <- fmt.Errorf("ΠMul-x Bob1 with %s: %w", pid, err)
			return
		}
		pp.kRhoShare[pp.myPos] = addMod(q, pp.kRhoShare[pp.myPos], uBK)
		pp.xRhoShare[pp.myPos] = addMod(q, pp.xRhoShare[pp.myPos], uBX)

		r3 := &signR3{BobK: encodeBobMsg(bMsgK), BobX: encodeBobMsg(bMsgX)}
		m := tss.JsonWrap(presignTypeR3, r3, Pi, pid)
		if err := pp.params.Broker().Receive(m); err != nil {
			pp.Err <- fmt.Errorf("broker r3→%s: %w", pid, err)
			return
		}
	}
	rcv := tss.NewJsonExpect[signR3](presignTypeR3, pp.otherSubset, pp.finalize)
	pp.params.Broker().Connect(presignTypeR3, rcv)
}

func (pp *PresignParty) finalize(otherIds []*tss.PartyID, msgs []*signR3) {
	if err := pp.ctx.Err(); err != nil {
		pp.Err <- err
		return
	}
	q := pp.params.EC().Params().N

	for n, pid := range otherIds {
		r3 := msgs[n]
		stK := pp.aliceStateK[peerKeyStr(pid)]
		stX := pp.aliceStateX[peerKeyStr(pid)]
		bobMsgK, err := decodeBobMsg(r3.BobK)
		if err != nil {
			pp.Err <- fmt.Errorf("decode Bob-k from %s: %w", pid, err)
			return
		}
		bobMsgX, err := decodeBobMsg(r3.BobX)
		if err != nil {
			pp.Err <- fmt.Errorf("decode Bob-x from %s: %w", pid, err)
			return
		}
		uAK, err := ole.AliceStep2(stK, bobMsgK)
		if err != nil {
			pp.Err <- fmt.Errorf("ΠMul-k Alice2 with %s: %w", pid, err)
			return
		}
		uAX, err := ole.AliceStep2(stX, bobMsgX)
		if err != nil {
			pp.Err <- fmt.Errorf("ΠMul-x Alice2 with %s: %w", pid, err)
			return
		}
		pp.kRhoShare[pp.myPos] = addMod(q, pp.kRhoShare[pp.myPos], uAK)
		pp.xRhoShare[pp.myPos] = addMod(q, pp.xRhoShare[pp.myPos], uAX)
	}

	// Assemble a single-party PresignOutput. The parties[] slice is
	// length 1 because each party holds only its own shares; the
	// SignWithPresign aggregation reveals the other parties' shares
	// via round-4 reveal (handled by an "online" sign party that runs
	// against this presign).
	//
	// aggregated is intentionally left false here — this output is NOT
	// directly consumable by SignWithPresign / SignWithPresignDurable;
	// both refuse to accept it. An online-sign protocol must compose
	// per-party shares from every signer to produce a verifying
	// signature.
	out := &PresignOutput{
		Pub:       pp.key.ECDSAPub,
		R:         pp.R,
		r:         new(big.Int).Set(pp.r),
		signerIdx: []int{pp.key.Idx},
		keys:      []*Key{pp.key},
		parties: []*partyPresign{
			{
				rho:       new(big.Int).Set(pp.rho_i),
				sigma:     new(big.Int).Set(pp.xRhoShare[pp.myPos]),
				kRhoShare: new(big.Int).Set(pp.kRhoShare[pp.myPos]),
			},
		},
		aggregated: false,
	}
	pp.Done <- out
}

func (pp *PresignParty) indexInFullCommittee(p *tss.PartyID) int {
	for i, q := range pp.key.PartyIDs {
		if q.KeyInt().Cmp(p.KeyInt()) == 0 {
			return i
		}
	}
	return -1
}

func presignSession(params *tss.Parameters, key *Key, subset tss.SortedPartyIDs) []byte {
	h := sha256.New()
	h.Write([]byte("DKLS23-presign-party-v1-"))
	h.Write(key.ECDSAPub.X().Bytes())
	h.Write(key.ECDSAPub.Y().Bytes())
	for _, p := range subset {
		h.Write(p.KeyInt().Bytes())
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

const (
	presignTypeR1 = "dkls:presign:r1"
	presignTypeR2 = "dkls:presign:r2"
	presignTypeR3 = "dkls:presign:r3"
)
