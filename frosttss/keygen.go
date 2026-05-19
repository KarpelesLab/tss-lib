package frosttss

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Keygen tracks a key currently being generated via the FROST Pedersen DKG
// (RFC 9591 Appendix D).
type Keygen struct {
	ctx    context.Context
	params *tss.Parameters
	vs     vss.Vs     // local polynomial commitments (Feldman)
	shares vss.Shares // local shares for every party
	a_i_0  *big.Int   // local secret coefficient — retained for the round-1 Schnorr PoK
	data   *Key

	Done chan *Key
	Err  chan error

	// Once-guards on Done/Err so multi-writer error paths cannot block on
	// the size-1 buffer. See once_send.go for the rationale.
	doneOnce sync.Once
	errOnce  sync.Once
}

// NewKeygen starts the FROST Pedersen DKG protocol for this party. Returns
// immediately after round 1 is broadcast; the result is delivered to Done (or
// an error to Err) once all rounds complete.
//
// The DKG produces an Ed25519 key whose public component is the value returned
// in Key.GroupPublicKey. Any standard Ed25519 verifier can verify signatures
// produced by frosttss.Signing under that public key.
func NewKeygen(ctx context.Context, params *tss.Parameters) (*Keygen, error) {
	if !tss.SameCurve(params.EC(), frost.EdwardsCurve()) {
		return nil, fmt.Errorf("frosttss: FROST(Ed25519) requires the Ed25519 curve")
	}
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

// round1 samples the local polynomial, broadcasts Feldman commitments and a
// Schnorr PoK of the constant coefficient a_{i,0}.
func (kg *Keygen) round1() error {
	Pi := kg.params.PartyID()
	i := Pi.Index
	ec := kg.params.EC()

	// Sample the polynomial via vss.Create. vss.Create returns Vs (Feldman
	// commitments = a_{i,j} * G) and Shares (f_i evaluated at each party's id).
	ids := kg.params.Parties().IDs().Keys()
	a_i_0 := common.GetRandomPositiveInt(kg.params.PartialKeyRand(), ec.Params().N)
	vs, shares, err := vss.Create(ec, kg.params.Threshold(), a_i_0, ids, kg.params.Rand())
	if err != nil {
		return fmt.Errorf("vss.Create: %w", err)
	}
	kg.data.Ks = ids
	kg.data.ShareID = ids[i]
	kg.vs = vs
	kg.shares = shares
	kg.a_i_0 = a_i_0

	// Schnorr PoK of a_{i,0} bound to phi_{i,0} = vs[0]. The Session string
	// encodes the FROST context plus the party's identifier so cross-party PoK
	// substitution attacks are impossible (RFC 9591 Appendix D.1).
	//
	// Note: crypto/schnorr.NewZKProof uses a different challenge hash than
	// RFC 9591's compute_proof_of_knowledge (it's the GG18 form already
	// audited in this repo). The proof is still a valid Schnorr PoK of the
	// same statement; we are not aiming for byte-level RFC-vector compatibility
	// for this internal PoK.
	session := buildKeygenSession(ids[i])
	pok, err := schnorr.NewZKProof(session, a_i_0, vs[0], kg.params.Rand())
	if err != nil {
		return fmt.Errorf("schnorr.NewZKProof: %w", err)
	}

	// Encode poly commitments as canonical 32-byte Ed25519 points.
	encodedCommitments := make([][]byte, len(vs))
	for j, v := range vs {
		encodedCommitments[j] = frost.EncodeElement(v)
	}

	// Build list of other parties.
	var otherIds []*tss.PartyID
	for n, p := range kg.params.Parties().IDs() {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
	}

	// Broadcast round 1 via a single To==nil message (identical bytes per
	// recipient).
	r1msg := &keygenRound1msg{
		PolyCommitments:    encodedCommitments,
		SchnorrProofAlphaX: pok.Alpha.X().Bytes(),
		SchnorrProofAlphaY: pok.Alpha.Y().Bytes(),
		SchnorrProofT:      pok.T.Bytes(),
	}
	m := tss.JsonWrap("frost:ed25519:keygen:round1", r1msg, Pi, nil)
	kg.params.Broker().Receive(m)

	// Register receiver for round 1 messages from all other parties.
	rcv := tss.NewJsonExpect[keygenRound1msg]("frost:ed25519:keygen:round1", otherIds, kg.round2)
	kg.params.Broker().Connect("frost:ed25519:keygen:round1", rcv)

	return nil
}

// round2 fires once round 1 has been received from every other party. It
// verifies each Schnorr PoK, then sends each other party their P2P share.
func (kg *Keygen) round2(otherIds []*tss.PartyID, r1msgs []*keygenRound1msg) {
	if kg.ctx.Err() != nil {
		sendOnce(&kg.errOnce, kg.Err, kg.ctx.Err())
		return
	}
	Pi := kg.params.PartyID()
	ec := kg.params.EC()

	// Decode and verify each peer's polynomial commitments + Schnorr PoK.
	peerVs := make([]vss.Vs, len(otherIds))
	for n, pid := range otherIds {
		r1 := r1msgs[n]
		if len(r1.PolyCommitments) != kg.params.Threshold()+1 {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent %d commitments, expected %d",
				pid, len(r1.PolyCommitments), kg.params.Threshold()+1))
			return
		}
		vsj := make(vss.Vs, len(r1.PolyCommitments))
		for k, enc := range r1.PolyCommitments {
			p, err := frost.DecodeElement(enc)
			if err != nil {
				sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent invalid poly commitment %d: %w", pid, k, err))
				return
			}
			// Cofactor-clear received points so any malicious-but-on-curve point
			// is projected into the prime-order subgroup. Legitimate points are
			// already in the subgroup so this is a no-op for honest senders.
			vsj[k] = p.EightInvEight()
		}
		peerVs[n] = vsj

		// Verify Schnorr PoK on the constant coefficient phi_{j,0} = vsj[0].
		session := buildKeygenSession(pid.KeyInt())
		alphaX := new(big.Int).SetBytes(r1.SchnorrProofAlphaX)
		alphaY := new(big.Int).SetBytes(r1.SchnorrProofAlphaY)
		alpha, err := crypto.NewECPoint(ec, alphaX, alphaY)
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent invalid Schnorr alpha: %w", pid, err))
			return
		}
		pok := &schnorr.ZKProof{Alpha: alpha, T: new(big.Int).SetBytes(r1.SchnorrProofT)}
		if !pok.Verify(session, vsj[0]) {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s Schnorr PoK verification failed", pid))
			return
		}
	}

	// Send each other party their P2P share. The share for party j is
	// f_i(x_j) — stored in kg.shares with ID == x_j.
	for _, Pj := range otherIds {
		var shareForPj *big.Int
		for _, sh := range kg.shares {
			if sh.ID.Cmp(Pj.KeyInt()) == 0 {
				shareForPj = sh.Share
				break
			}
		}
		if shareForPj == nil {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("internal: missing share for party %s", Pj))
			return
		}
		r2 := &keygenRound2msg{Share: shareForPj.Bytes()}
		m := tss.JsonWrap("frost:ed25519:keygen:round2", r2, Pi, Pj)
		kg.params.Broker().Receive(m)
	}

	// Register receiver for round 2 P2P shares from all others.
	rcv := tss.NewJsonExpect[keygenRound2msg]("frost:ed25519:keygen:round2", otherIds, func(ids []*tss.PartyID, msgs []*keygenRound2msg) {
		kg.finalize(otherIds, peerVs, ids, msgs)
	})
	kg.params.Broker().Connect("frost:ed25519:keygen:round2", rcv)
}

// finalize verifies received shares against their senders' Feldman commitments,
// aggregates into Xi, BigXj, and the group public key.
func (kg *Keygen) finalize(
	r1Ids []*tss.PartyID, peerVs []vss.Vs,
	r2Ids []*tss.PartyID, r2msgs []*keygenRound2msg,
) {
	if kg.ctx.Err() != nil {
		sendOnce(&kg.errOnce, kg.Err, kg.ctx.Err())
		return
	}
	ec := kg.params.EC()
	PIdx := kg.params.PartyID().Index
	modQ := common.ModInt(ec.Params().N)

	// r1Ids and r2Ids should contain the same parties. Build a map identifier
	// string -> vs so we can resolve r2Ids back to the corresponding peerVs.
	vsByID := make(map[string]vss.Vs, len(r1Ids))
	for n, pid := range r1Ids {
		vsByID[pid.KeyInt().String()] = peerVs[n]
	}

	// Verify each P2P share against its sender's Feldman commitments and
	// accumulate into our Xi.
	xi := new(big.Int).Set(kg.shares[PIdx].Share)
	for n, pid := range r2Ids {
		vsj, ok := vsByID[pid.KeyInt().String()]
		if !ok {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("share from party %s had no matching round-1 commitments", pid))
			return
		}
		shareInt := new(big.Int).SetBytes(r2msgs[n].Share)
		shareCheck := &vss.Share{
			Threshold: kg.params.Threshold(),
			ID:        kg.data.ShareID,
			Share:     shareInt,
		}
		if !shareCheck.Verify(ec, kg.params.Threshold(), vsj) {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("VSS share verification failed for party %s", pid))
			return
		}
		xi = modQ.Add(xi, shareInt)
	}
	kg.data.Xi = xi

	// Aggregate Feldman commitments column-wise: Vc[c] = sum_j vs_j[c].
	Vc := make(vss.Vs, kg.params.Threshold()+1)
	for c := range Vc {
		Vc[c] = kg.vs[c]
	}
	for _, vsj := range peerVs {
		for c := 0; c <= kg.params.Threshold(); c++ {
			sum, err := Vc[c].Add(vsj[c])
			if err != nil {
				sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("aggregating Vc[%d]: %w", c, err))
				return
			}
			Vc[c] = sum
		}
	}

	// Derive every party's verification share BigXj = sum_c (k_j)^c * Vc[c].
	for j := 0; j < kg.params.PartyCount(); j++ {
		kj := kg.params.Parties().IDs()[j].KeyInt()
		BigXj := Vc[0]
		z := big.NewInt(1)
		for c := 1; c <= kg.params.Threshold(); c++ {
			z = modQ.Mul(z, kj)
			next, err := BigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("computing BigXj for party %d: %w", j, err))
				return
			}
			BigXj = next
		}
		kg.data.BigXj[j] = BigXj
	}

	// GroupPublicKey = Vc[0] (sum of constant coefficients * G).
	pub, err := crypto.NewECPoint(ec, Vc[0].X(), Vc[0].Y())
	if err != nil {
		sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("group public key not on curve: %w", err))
		return
	}
	kg.data.GroupPublicKey = pub

	// a_i_0 is no longer needed.
	kg.a_i_0 = nil

	sendOnce(&kg.doneOnce, kg.Done, kg.data)
}

// buildKeygenSession returns a fixed-format Session byte string for the
// Schnorr PoK on a_i,0 in DKG round 1. Including the party identifier prevents
// PoK reuse across parties; including the FROST ContextString prevents reuse
// across protocols.
func buildKeygenSession(partyKey *big.Int) []byte {
	var s []byte
	s = append(s, frost.ContextString...)
	s = append(s, []byte("dkg-pok")...)
	s = append(s, partyKey.Bytes()...)
	return s
}
