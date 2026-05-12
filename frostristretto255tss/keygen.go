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

// Keygen tracks a key currently being generated via FROST Pedersen DKG over
// Ristretto255 (RFC 9591 Appendix D).
type Keygen struct {
	ctx    context.Context
	params *tss.Parameters
	vs     []group.Element // local polynomial commitments
	shares []*vssShare     // local shares for every party
	a_i_0  *big.Int        // local secret coefficient — kept for the round-1 PoK
	data   *Key

	Done chan *Key
	Err  chan error
}

// NewKeygen starts the FROST(ristretto255) Pedersen DKG. The params.EC()
// curve is treated as a placeholder; this package always operates over
// crypto/group.Ristretto255().
func NewKeygen(ctx context.Context, params *tss.Parameters) (*Keygen, error) {
	kg := &Keygen{
		ctx:    ctx,
		params: params,
		data:   NewKey(params.PartyCount()),
		Done:   make(chan *Key, 1),
		Err:    make(chan error, 1),
	}
	if err := kg.round1(); err != nil {
		return nil, err
	}
	return kg, nil
}

func (kg *Keygen) round1() error {
	Pi := kg.params.PartyID()
	i := Pi.Index
	g := group.Ristretto255()

	ids := kg.params.Parties().IDs().Keys()
	a_i_0 := g.RandomScalar(kg.params.PartialKeyRand())
	vs, shares, err := vssCreate(g, kg.params.Threshold(), a_i_0, ids, kg.params.Rand())
	if err != nil {
		return fmt.Errorf("vssCreate: %w", err)
	}
	kg.data.Ks = ids
	kg.data.ShareID = ids[i]
	kg.vs = vs
	kg.shares = shares
	kg.a_i_0 = a_i_0

	session := buildKeygenSession(ids[i])
	pok, err := schnorrProve(g, session, a_i_0, vs[0], kg.params.Rand())
	if err != nil {
		return fmt.Errorf("schnorrProve: %w", err)
	}

	encodedCommitments := make([][]byte, len(vs))
	for j, v := range vs {
		encodedCommitments[j] = v.Bytes()
	}

	var otherIds []*tss.PartyID
	for n, p := range kg.params.Parties().IDs() {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	r1 := &keygenRound1msg{
		PolyCommitments: encodedCommitments,
		SchnorrR:        pok.R.Bytes(),
		SchnorrT:        g.EncodeScalar(pok.T),
	}
	for _, p := range otherIds {
		m := tss.JsonWrap("frost:ristretto255:keygen:round1", r1, Pi, p)
		kg.params.Broker().Receive(m)
	}

	rcv := tss.NewJsonExpect[keygenRound1msg]("frost:ristretto255:keygen:round1", otherIds, kg.round2)
	kg.params.Broker().Connect("frost:ristretto255:keygen:round1", rcv)
	return nil
}

func (kg *Keygen) round2(otherIds []*tss.PartyID, r1msgs []*keygenRound1msg) {
	if kg.ctx.Err() != nil {
		kg.Err <- kg.ctx.Err()
		return
	}
	Pi := kg.params.PartyID()
	g := group.Ristretto255()

	peerVs := make([][]group.Element, len(otherIds))
	for n, pid := range otherIds {
		r1 := r1msgs[n]
		if len(r1.PolyCommitments) != kg.params.Threshold()+1 {
			kg.Err <- fmt.Errorf("party %s sent %d commitments, expected %d",
				pid, len(r1.PolyCommitments), kg.params.Threshold()+1)
			return
		}
		vsj := make([]group.Element, len(r1.PolyCommitments))
		for k, enc := range r1.PolyCommitments {
			el, err := g.DecodeElement(enc)
			if err != nil {
				kg.Err <- fmt.Errorf("party %s sent invalid poly commitment %d: %w", pid, k, err)
				return
			}
			vsj[k] = el
		}
		peerVs[n] = vsj

		Rj, err := g.DecodeElement(r1.SchnorrR)
		if err != nil {
			kg.Err <- fmt.Errorf("party %s sent invalid Schnorr R: %w", pid, err)
			return
		}
		Tj, err := g.DecodeScalar(r1.SchnorrT)
		if err != nil {
			kg.Err <- fmt.Errorf("party %s sent invalid Schnorr T: %w", pid, err)
			return
		}
		session := buildKeygenSession(pid.KeyInt())
		if !schnorrVerify(g, session, vsj[0], &schnorrProof{R: Rj, T: Tj}) {
			kg.Err <- fmt.Errorf("party %s Schnorr PoK verification failed", pid)
			return
		}
	}

	for _, Pj := range otherIds {
		var shareForPj *big.Int
		for _, sh := range kg.shares {
			if sh.ID.Cmp(Pj.KeyInt()) == 0 {
				shareForPj = sh.Share
				break
			}
		}
		if shareForPj == nil {
			kg.Err <- fmt.Errorf("internal: missing share for party %s", Pj)
			return
		}
		r2 := &keygenRound2msg{Share: g.EncodeScalar(shareForPj)}
		m := tss.JsonWrap("frost:ristretto255:keygen:round2", r2, Pi, Pj)
		kg.params.Broker().Receive(m)
	}

	rcv := tss.NewJsonExpect[keygenRound2msg]("frost:ristretto255:keygen:round2", otherIds, func(ids []*tss.PartyID, msgs []*keygenRound2msg) {
		kg.finalize(otherIds, peerVs, ids, msgs)
	})
	kg.params.Broker().Connect("frost:ristretto255:keygen:round2", rcv)
}

func (kg *Keygen) finalize(
	r1Ids []*tss.PartyID, peerVs [][]group.Element,
	r2Ids []*tss.PartyID, r2msgs []*keygenRound2msg,
) {
	if kg.ctx.Err() != nil {
		kg.Err <- kg.ctx.Err()
		return
	}
	g := group.Ristretto255()
	PIdx := kg.params.PartyID().Index
	modQ := common.ModInt(g.Order())

	vsByID := make(map[string][]group.Element, len(r1Ids))
	for n, pid := range r1Ids {
		vsByID[pid.KeyInt().String()] = peerVs[n]
	}

	xi := new(big.Int).Set(kg.shares[PIdx].Share)
	for n, pid := range r2Ids {
		vsj, ok := vsByID[pid.KeyInt().String()]
		if !ok {
			kg.Err <- fmt.Errorf("share from party %s had no matching round-1 commitments", pid)
			return
		}
		shareInt, err := g.DecodeScalar(r2msgs[n].Share)
		if err != nil {
			kg.Err <- fmt.Errorf("party %s sent invalid share: %w", pid, err)
			return
		}
		sh := &vssShare{
			Threshold: kg.params.Threshold(),
			ID:        kg.data.ShareID,
			Share:     shareInt,
		}
		if !sh.verify(g, kg.params.Threshold(), vsj) {
			kg.Err <- fmt.Errorf("VSS share verification failed for party %s", pid)
			return
		}
		xi = modQ.Add(xi, shareInt)
	}
	kg.data.Xi = xi

	// Aggregate Vc[c] = sum_j vs_j[c].
	Vc := make([]group.Element, kg.params.Threshold()+1)
	for c := range Vc {
		Vc[c] = kg.vs[c].Clone()
	}
	for _, vsj := range peerVs {
		for c := 0; c <= kg.params.Threshold(); c++ {
			sum, err := Vc[c].Add(vsj[c])
			if err != nil {
				kg.Err <- fmt.Errorf("aggregating Vc[%d]: %w", c, err)
				return
			}
			Vc[c] = sum
		}
	}

	// Derive every party's verification share BigXj = sum_c (k_j)^c * Vc[c].
	for j := 0; j < kg.params.PartyCount(); j++ {
		kj := kg.params.Parties().IDs()[j].KeyInt()
		BigXj := Vc[0].Clone()
		z := big.NewInt(1)
		for c := 1; c <= kg.params.Threshold(); c++ {
			z = modQ.Mul(z, kj)
			next, err := BigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				kg.Err <- fmt.Errorf("computing BigXj for party %d: %w", j, err)
				return
			}
			BigXj = next
		}
		kg.data.BigXj[j] = BigXj
	}
	kg.data.GroupPublicKey = Vc[0]
	kg.a_i_0 = nil
	kg.Done <- kg.data
}

func buildKeygenSession(partyKey *big.Int) []byte {
	var s []byte
	s = append(s, frost.Ristretto255ContextString...)
	s = append(s, []byte("dkg-pok")...)
	s = append(s, partyKey.Bytes()...)
	return s
}
