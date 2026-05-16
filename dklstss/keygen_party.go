package dklstss

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// KeygenParty is the per-party DKG state machine that runs over a
// tss.MessageBroker. Each party constructs its own *KeygenParty with
// its own tss.Parameters; messages are exchanged via params.Broker().
// On completion, the resulting Key is delivered on Done (or an error
// on Err).
//
// This is the broker-driven equivalent of the synchronous Keygen()
// function. The synchronous version is retained for tests that run
// all parties in one goroutine; this Party-based API matches the
// ecdsatss/eddsatss/frosttss convention and is suited to genuinely
// distributed deployments.
type KeygenParty struct {
	ctx    context.Context
	params *tss.Parameters
	ssid   []byte

	u_i     *big.Int
	vs      vss.Vs
	shares  vss.Shares
	baseSnd map[string]*baseot.Sender // peerKey → base-OT Sender state for direction "peer = OT-Ext-Sender"

	peerVs     map[string]vss.Vs
	peerShares map[string]*big.Int

	baseRcv map[string]*baseot.Receiver // peerKey → base-OT Receiver state for direction "i = OT-Ext-Sender"
	myDelta map[string][]byte           // peerKey → Δ used for above

	Done chan *Key
	Err  chan error
}

// NewKeygen kicks off DKG for the local party. Returns immediately;
// the result is delivered on Done or Err.
//
// Requirements: params.PartyID() is the local party; params.Parties()
// includes everyone in sorted order; params.Broker() is configured
// (tests use tss.NewTestBroker()); params.EC() is secp256k1.
func NewKeygen(ctx context.Context, params *tss.Parameters) (*KeygenParty, error) {
	if ctx == nil {
		return nil, errors.New("dklstss: NewKeygen nil context")
	}
	if params == nil {
		return nil, errors.New("dklstss: NewKeygen nil params")
	}
	if !tss.SameCurve(params.EC(), tss.S256()) {
		return nil, fmt.Errorf("dklstss: NewKeygen requires secp256k1 curve")
	}
	kg := &KeygenParty{
		ctx:        ctx,
		params:     params,
		ssid:       keygenSession(params),
		baseSnd:    make(map[string]*baseot.Sender),
		baseRcv:    make(map[string]*baseot.Receiver),
		myDelta:    make(map[string][]byte),
		peerVs:     make(map[string]vss.Vs),
		peerShares: make(map[string]*big.Int),
		Done:       make(chan *Key, 1),
		Err:        make(chan error, 1),
	}
	if err := kg.round1(); err != nil {
		return nil, fmt.Errorf("dklstss: NewKeygen round1: %w", err)
	}
	return kg, nil
}

func (kg *KeygenParty) round1() error {
	Pi := kg.params.PartyID()
	ec := kg.params.EC()
	threshold := kg.params.Threshold()
	q := ec.Params().N

	ids := kg.params.Parties().IDs().Keys()
	if _, err := vss.CheckIndexes(ec, ids); err != nil {
		return fmt.Errorf("invalid party indexes: %w", err)
	}

	u_i := common.GetRandomPositiveInt(kg.params.PartialKeyRand(), q)
	vs, shares, err := vss.Create(ec, threshold, u_i, ids, kg.params.Rand())
	if err != nil {
		return fmt.Errorf("vss.Create: %w", err)
	}
	kg.u_i = u_i
	kg.vs = vs
	kg.shares = shares

	encCommit := flattenPointXY(vs)

	otherIds := otherPartyIDs(kg.params)
	for _, Pj := range otherIds {
		shareForJ, err := findShareValue(kg.shares, Pj.KeyInt())
		if err != nil {
			return fmt.Errorf("internal: %w", err)
		}
		// Direction "j becomes ExtSender, i becomes ExtReceiver":
		// base-OT roles → i is base-OT Sender.
		sid := pairBaseSid(kg.ssid, Pi.KeyInt(), Pj.KeyInt(), Pj.KeyInt())
		snd, sndMsg, err := baseot.NewSender(sid, otext.Kappa, kg.params.Rand())
		if err != nil {
			return fmt.Errorf("baseot.NewSender for %s: %w", Pj, err)
		}
		kg.baseSnd[peerKeyStr(Pj)] = snd

		r1 := &keygenR1{
			VSSCommitments: encCommit,
			Share:          shareForJ.Bytes(),
			OTSenderSX:     sndMsg.S.X().Bytes(),
			OTSenderSY:     sndMsg.S.Y().Bytes(),
			OTSenderPokAX:  sndMsg.PoK.Alpha.X().Bytes(),
			OTSenderPokAY:  sndMsg.PoK.Alpha.Y().Bytes(),
			OTSenderPokT:   sndMsg.PoK.T.Bytes(),
		}
		m := tss.JsonWrap(keygenTypeR1, r1, Pi, Pj)
		if err := kg.params.Broker().Receive(m); err != nil {
			return fmt.Errorf("broker.Receive r1→%s: %w", Pj, err)
		}
	}

	rcv := tss.NewJsonExpect[keygenR1](keygenTypeR1, otherIds, kg.round2)
	kg.params.Broker().Connect(keygenTypeR1, rcv)
	return nil
}

func (kg *KeygenParty) round2(otherIds []*tss.PartyID, msgs []*keygenR1) {
	if err := kg.ctx.Err(); err != nil {
		kg.Err <- err
		return
	}
	Pi := kg.params.PartyID()
	ec := kg.params.EC()
	threshold := kg.params.Threshold()

	for n, pid := range otherIds {
		r1 := msgs[n]

		if len(r1.VSSCommitments) != 2*(threshold+1) {
			kg.Err <- fmt.Errorf("party %s sent %d VSS-commitment coords, expected %d",
				pid, len(r1.VSSCommitments), 2*(threshold+1))
			return
		}
		vsj, err := unflattenPointXY(ec, r1.VSSCommitments)
		if err != nil {
			kg.Err <- fmt.Errorf("party %s VSS commitments decode: %w", pid, err)
			return
		}

		shareInt := new(big.Int).SetBytes(r1.Share)
		sh := &vss.Share{Threshold: threshold, ID: Pi.KeyInt(), Share: shareInt}
		if !sh.Verify(ec, threshold, vsj) {
			kg.Err <- fmt.Errorf("party %s VSS share verification failed", pid)
			return
		}

		Sj, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(r1.OTSenderSX),
			new(big.Int).SetBytes(r1.OTSenderSY))
		if err != nil {
			kg.Err <- fmt.Errorf("party %s OT Sender S invalid: %w", pid, err)
			return
		}
		alpha, err := crypto.NewECPoint(ec,
			new(big.Int).SetBytes(r1.OTSenderPokAX),
			new(big.Int).SetBytes(r1.OTSenderPokAY))
		if err != nil {
			kg.Err <- fmt.Errorf("party %s OT Sender PoK alpha invalid: %w", pid, err)
			return
		}
		pok := &schnorr.ZKProof{Alpha: alpha, T: new(big.Int).SetBytes(r1.OTSenderPokT)}
		// Peer's Sj corresponds to direction "i is ExtSender" — sid
		// names i as the OT-Ext-Sender.
		sid := pairBaseSid(kg.ssid, pid.KeyInt(), Pi.KeyInt(), Pi.KeyInt())
		sndMsg := &baseot.SenderMsg1{S: Sj, PoK: pok}

		delta := make([]byte, otext.DeltaBytes)
		if _, err := kg.params.Rand().Read(delta); err != nil {
			kg.Err <- fmt.Errorf("randomness: %w", err)
			return
		}
		rcvr, rcvMsg, err := baseot.NewReceiver(sid, otext.Kappa, delta, sndMsg, kg.params.Rand())
		if err != nil {
			kg.Err <- fmt.Errorf("party %s base-OT receiver setup: %w", pid, err)
			return
		}
		kg.baseRcv[peerKeyStr(pid)] = rcvr
		kg.myDelta[peerKeyStr(pid)] = delta
		kg.peerVs[peerKeyStr(pid)] = vsj
		kg.peerShares[peerKeyStr(pid)] = shareInt

		r2 := &keygenR2{OTReceiverR: flattenPointXY(rcvMsg.R)}
		m := tss.JsonWrap(keygenTypeR2, r2, Pi, pid)
		if err := kg.params.Broker().Receive(m); err != nil {
			kg.Err <- fmt.Errorf("broker.Receive r2→%s: %w", pid, err)
			return
		}
	}

	rcv := tss.NewJsonExpect[keygenR2](keygenTypeR2, otherIds, kg.finalize)
	kg.params.Broker().Connect(keygenTypeR2, rcv)
}

func (kg *KeygenParty) finalize(otherIds []*tss.PartyID, msgs []*keygenR2) {
	if err := kg.ctx.Err(); err != nil {
		kg.Err <- err
		return
	}
	Pi := kg.params.PartyID()
	ec := kg.params.EC()
	threshold := kg.params.Threshold()
	q := ec.Params().N
	parties := kg.params.Parties().IDs()
	n := len(parties)

	selfIdx := Pi.Index
	xi := new(big.Int).Set(kg.shares[selfIdx].Share)
	for _, pid := range otherIds {
		xi.Add(xi, kg.peerShares[peerKeyStr(pid)])
		xi.Mod(xi, q)
	}

	pub := kg.vs[0]
	for _, pid := range otherIds {
		var err error
		pub, err = pub.Add(kg.peerVs[peerKeyStr(pid)][0])
		if err != nil {
			kg.Err <- fmt.Errorf("aggregate pubkey: %w", err)
			return
		}
	}

	allVss := make([]vss.Vs, n)
	for _, pid := range parties {
		if pid.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			allVss[pid.Index] = kg.vs
		} else {
			allVss[pid.Index] = kg.peerVs[peerKeyStr(pid)]
		}
	}
	BigXj := make([]*crypto.ECPoint, n)
	for _, pid := range parties {
		Xj, err := evaluateCommitmentSum(ec, allVss, pid.KeyInt())
		if err != nil {
			kg.Err <- fmt.Errorf("BigXj[%d]: %w", pid.Index, err)
			return
		}
		BigXj[pid.Index] = Xj
	}

	ot := make([]*PairOTState, n)
	for _, pj := range otherIds {
		peerk := peerKeyStr(pj)

		// Direction "i is ExtSender": local base-OT Receiver finalizes.
		chosen, err := kg.baseRcv[peerk].Finalize()
		if err != nil {
			kg.Err <- fmt.Errorf("base-OT receiver finalize for %s: %w", pj, err)
			return
		}
		extSender, err := otext.NewExtSenderFromBase(kg.myDelta[peerk], chosen)
		if err != nil {
			kg.Err <- fmt.Errorf("ExtSender for %s: %w", pj, err)
			return
		}

		// Direction "peer is ExtSender": local base-OT Sender finalizes
		// with peer's round-2 R-points.
		var r2 *keygenR2
		for idx, pid := range otherIds {
			if pid.KeyInt().Cmp(pj.KeyInt()) == 0 {
				r2 = msgs[idx]
				break
			}
		}
		if r2 == nil {
			kg.Err <- fmt.Errorf("missing round-2 message from %s", pj)
			return
		}
		rPoints, err := unflattenPointXY(ec, r2.OTReceiverR)
		if err != nil {
			kg.Err <- fmt.Errorf("decode R from %s: %w", pj, err)
			return
		}
		k0, k1, err := kg.baseSnd[peerk].Finalize(&baseot.ReceiverMsg1{R: rPoints})
		if err != nil {
			kg.Err <- fmt.Errorf("base-OT sender finalize for %s: %w", pj, err)
			return
		}
		extReceiver, err := otext.NewExtReceiverFromBase(k0, k1)
		if err != nil {
			kg.Err <- fmt.Errorf("ExtReceiver for %s: %w", pj, err)
			return
		}

		ot[pj.Index] = &PairOTState{AsAlice: extReceiver, AsBob: extSender}
	}

	chainCode := deriveChainCode(pub)
	key := &Key{
		Curve:     ec,
		N:         n,
		T:         threshold,
		Idx:       selfIdx,
		PartyIDs:  parties,
		Xi:        xi,
		BigXj:     BigXj,
		ECDSAPub:  pub,
		OT:        ot,
		ChainCode: chainCode,
	}
	if err := key.ValidateBasic(); err != nil {
		kg.Err <- fmt.Errorf("finalize ValidateBasic: %w", err)
		return
	}
	kg.Done <- key
}

// --- wire types ----------------------------------------------------

type keygenR1 struct {
	VSSCommitments [][]byte `json:"vss_commitments"`
	Share          []byte   `json:"share"`
	OTSenderSX     []byte   `json:"ot_sender_s_x"`
	OTSenderSY     []byte   `json:"ot_sender_s_y"`
	OTSenderPokAX  []byte   `json:"ot_sender_pok_alpha_x"`
	OTSenderPokAY  []byte   `json:"ot_sender_pok_alpha_y"`
	OTSenderPokT   []byte   `json:"ot_sender_pok_t"`
}

type keygenR2 struct {
	OTReceiverR [][]byte `json:"ot_receiver_r"`
}

const (
	keygenTypeR1 = "dkls:keygen:r1"
	keygenTypeR2 = "dkls:keygen:r2"
)

// --- helpers --------------------------------------------------------

func keygenSession(params *tss.Parameters) []byte {
	h := sha256.New()
	h.Write([]byte("DKLS23-keygen-party-v1-"))
	for _, p := range params.Parties().IDs() {
		h.Write(p.KeyInt().Bytes())
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

func otherPartyIDs(params *tss.Parameters) []*tss.PartyID {
	self := params.PartyID()
	var out []*tss.PartyID
	for _, p := range params.Parties().IDs() {
		if p.KeyInt().Cmp(self.KeyInt()) == 0 {
			continue
		}
		out = append(out, p)
	}
	return out
}

func peerKeyStr(p *tss.PartyID) string { return p.KeyInt().String() }

func pairBaseSid(ssid []byte, a, b, extSenderID *big.Int) []byte {
	h := sha256.New()
	h.Write(ssid)
	h.Write([]byte{'|'})
	if a.Cmp(b) <= 0 {
		h.Write(a.Bytes())
		h.Write([]byte{'|'})
		h.Write(b.Bytes())
	} else {
		h.Write(b.Bytes())
		h.Write([]byte{'|'})
		h.Write(a.Bytes())
	}
	h.Write([]byte{'|'})
	h.Write(extSenderID.Bytes())
	return h.Sum(nil)
}

func findShareValue(shares vss.Shares, id *big.Int) (*big.Int, error) {
	for _, s := range shares {
		if s.ID.Cmp(id) == 0 {
			return s.Share, nil
		}
	}
	return nil, fmt.Errorf("no share for id %s", id.String())
}

func flattenPointXY(pts []*crypto.ECPoint) [][]byte {
	out := make([][]byte, 0, 2*len(pts))
	for _, p := range pts {
		if p == nil {
			out = append(out, nil, nil)
			continue
		}
		out = append(out, p.X().Bytes(), p.Y().Bytes())
	}
	return out
}

func unflattenPointXY(ec elliptic.Curve, flat [][]byte) ([]*crypto.ECPoint, error) {
	if len(flat)%2 != 0 {
		return nil, fmt.Errorf("flat point slice length %d not even", len(flat))
	}
	out := make([]*crypto.ECPoint, 0, len(flat)/2)
	for i := 0; i < len(flat); i += 2 {
		x := new(big.Int).SetBytes(flat[i])
		y := new(big.Int).SetBytes(flat[i+1])
		p, err := crypto.NewECPoint(ec, x, y)
		if err != nil {
			return nil, fmt.Errorf("point [%d] off-curve: %w", i/2, err)
		}
		out = append(out, p)
	}
	return out, nil
}
