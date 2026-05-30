package frostristretto255tss

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frostenc"
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

	// Ephemeral X25519 keypair for the round-2 encrypted-share envelope.
	// Sampled fresh per keygen run. ephPriv is zeroized at finalize.
	ephPriv []byte
	ephPub  []byte
	// peerEphPubs maps each peer's KeyInt().String() to their broadcast
	// EphPub from round 1, so round 2 can look up the recipient key.
	peerEphPubs map[string][]byte
	// peerSessionNonces parallel to peerEphPubs: per-peer SessionNonce for AD
	// reconstruction in finalize.
	peerSessionNonces map[string][]byte
	// mySessionNonce is the local SessionNonce broadcast in round 1, mixed
	// into the PoK challenge and the round-2 AD binding.
	mySessionNonce []byte

	Done chan *Key
	Err  chan error

	// Once-guards on Done/Err so multi-writer error paths cannot block on
	// the size-1 buffer. See once_send.go for the rationale.
	doneOnce sync.Once
	errOnce  sync.Once
}

// keygenRound2AD constructs the associated-data bytes for the encrypted
// round-2 share envelope. Binding (sessionNonceOfDealer || senderPub ||
// recipientPub) makes the ciphertext non-replayable across (run, sender,
// recipient). Mirrors frosttss/keygen.go keygenRound2AD.
func keygenRound2AD(senderSessionNonce, senderPub, recipientPub []byte) []byte {
	ad := make([]byte, 0,
		len("frostristretto255tss/keygen/r2/v1|")+
			len(senderSessionNonce)+len(senderPub)+len(recipientPub)+2)
	ad = append(ad, []byte("frostristretto255tss/keygen/r2/v1|")...)
	ad = append(ad, senderSessionNonce...)
	ad = append(ad, '|')
	ad = append(ad, senderPub...)
	ad = append(ad, '|')
	ad = append(ad, recipientPub...)
	return ad
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

	// Sample a fresh per-keygen session nonce. Broadcast in round 1 and folded
	// (length-prefixed) into the PoK challenge so the proof is run-unique;
	// breaks PoK replay across keygen runs with the same party set.
	sessionNonce := make([]byte, keygenSessionNonceLen)
	if _, err := kg.params.Rand().Read(sessionNonce); err != nil {
		return fmt.Errorf("rand for session nonce: %w", err)
	}

	// Sample a fresh ephemeral X25519 keypair. Its public component is
	// broadcast in round 1 and used by every other party to derive a per-pair
	// AEAD key for the encrypted round-2 P2P share envelope. Without this,
	// round-2 shares would be sent in cleartext and a passive eavesdropper plus
	// t-1 corrupted parties could recover the master secret.
	ephPriv, ephPub, err := frostenc.NewEphemeralKey(kg.params.Rand())
	if err != nil {
		return fmt.Errorf("frostenc.NewEphemeralKey: %w", err)
	}
	kg.ephPriv = ephPriv
	kg.ephPub = ephPub
	kg.mySessionNonce = sessionNonce

	session := buildKeygenSession(ids[i], sessionNonce)
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

	// Broadcast round 1 via a single To==nil message — see frosttss/keygen.go.
	r1 := &keygenRound1msg{
		PolyCommitments: encodedCommitments,
		SessionNonce:    sessionNonce,
		EphPub:          ephPub,
		SchnorrR:        pok.R.Bytes(),
		SchnorrT:        g.EncodeScalar(pok.T),
	}
	m := tss.JsonWrap("frost:ristretto255:keygen:round1", r1, Pi, nil)
	kg.params.Broker().Receive(m)

	rcv := tss.NewJsonExpect[keygenRound1msg]("frost:ristretto255:keygen:round1", otherIds, kg.round2)
	kg.params.Broker().Connect("frost:ristretto255:keygen:round1", rcv)
	return nil
}

func (kg *Keygen) round2(otherIds []*tss.PartyID, r1msgs []*keygenRound1msg) {
	if kg.ctx.Err() != nil {
		sendOnce(&kg.errOnce, kg.Err, kg.ctx.Err())
		return
	}
	Pi := kg.params.PartyID()
	g := group.Ristretto255()

	peerVs := make([][]group.Element, len(otherIds))
	kg.peerEphPubs = make(map[string][]byte, len(otherIds))
	kg.peerSessionNonces = make(map[string][]byte, len(otherIds))
	for n, pid := range otherIds {
		r1 := r1msgs[n]
		if len(r1.PolyCommitments) != kg.params.Threshold()+1 {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent %d commitments, expected %d",
				pid, len(r1.PolyCommitments), kg.params.Threshold()+1))
			return
		}
		// Session nonce length check — empty / wrong-length is a protocol
		// violation. Needed both for the PoK challenge and the round-2 AD.
		if len(r1.SessionNonce) != keygenSessionNonceLen {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent session nonce of length %d (want %d)",
				pid, len(r1.SessionNonce), keygenSessionNonceLen))
			return
		}
		// EphPub length check.
		if len(r1.EphPub) != frostenc.EphemeralKeyBytes {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent EphPub of length %d (want %d)",
				pid, len(r1.EphPub), frostenc.EphemeralKeyBytes))
			return
		}
		kg.peerEphPubs[pid.KeyInt().String()] = r1.EphPub
		kg.peerSessionNonces[pid.KeyInt().String()] = r1.SessionNonce
		vsj := make([]group.Element, len(r1.PolyCommitments))
		for k, enc := range r1.PolyCommitments {
			el, err := g.DecodeElement(enc)
			if err != nil {
				sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent invalid poly commitment %d: %w", pid, k, err))
				return
			}
			vsj[k] = el
		}
		// Identity-element rejection: a dealer that publishes phi_{j,0} =
		// identity contributes zero to the joint secret. The Schnorr PoK on
		// the constant coefficient passes with witness 0, so without this
		// explicit check a colluding dealer could effectively skip its
		// contribution to the joint key. Reject every dealer whose phi_{j,0}
		// resolves to the identity. Mirrors frosttss/keygen.go round2.
		if vsj[0].IsIdentity() {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s round-1 phi_{j,0} is the group identity (rogue-zero contribution)", pid))
			return
		}
		peerVs[n] = vsj

		Rj, err := g.DecodeElement(r1.SchnorrR)
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent invalid Schnorr R: %w", pid, err))
			return
		}
		Tj, err := g.DecodeScalar(r1.SchnorrT)
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent invalid Schnorr T: %w", pid, err))
			return
		}
		// Verify the PoK against the peer's broadcast session nonce. Distinct
		// nonces produce distinct challenges; an attacker cannot replay an old
		// PoK because the old broadcast carried an old nonce.
		session := buildKeygenSession(pid.KeyInt(), r1.SessionNonce)
		if !schnorrVerify(g, session, vsj[0], &schnorrProof{R: Rj, T: Tj}) {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s Schnorr PoK verification failed", pid))
			return
		}
	}

	// Send each other party their P2P share, sealed under the
	// (kg.ephPriv, peer's EphPub) X25519+ChaCha20-Poly1305 envelope so a
	// passive eavesdropper on the broker cannot recover the share.
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
		recipientPub, ok := kg.peerEphPubs[Pj.KeyInt().String()]
		if !ok {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("internal: missing peer EphPub for %s", Pj))
			return
		}
		ad := keygenRound2AD(kg.mySessionNonce, kg.ephPub, recipientPub)
		plaintext := g.EncodeScalar(shareForPj)
		ct, err := frostenc.SealShare(kg.params.Rand(), kg.ephPriv, recipientPub, ad, plaintext)
		// Best-effort zeroize the plaintext copy on this goroutine stack.
		for i := range plaintext {
			plaintext[i] = 0
		}
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("seal share to %s: %w", Pj, err))
			return
		}
		r2 := &keygenRound2msg{Ciphertext: ct}
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
		sendOnce(&kg.errOnce, kg.Err, kg.ctx.Err())
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
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("share from party %s had no matching round-1 commitments", pid))
			return
		}
		// Decrypt the P2P share. AD is reconstructed from the sender's
		// SessionNonce and EphPub (snapshotted in round 2) plus our own EphPub.
		senderSessionNonce, ok := kg.peerSessionNonces[pid.KeyInt().String()]
		if !ok {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("share from %s: missing peer session nonce", pid))
			return
		}
		senderPub, ok := kg.peerEphPubs[pid.KeyInt().String()]
		if !ok {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("share from %s: missing peer EphPub", pid))
			return
		}
		ad := keygenRound2AD(senderSessionNonce, senderPub, kg.ephPub)
		shareBytes, err := frostenc.OpenShare(kg.ephPriv, senderPub, ad, r2msgs[n].Ciphertext)
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s share ciphertext failed to open: %w", pid, err))
			return
		}
		shareInt, err := g.DecodeScalar(shareBytes)
		// Best-effort zeroize the plaintext bytes immediately.
		for i := range shareBytes {
			shareBytes[i] = 0
		}
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("party %s sent invalid share: %w", pid, err))
			return
		}
		sh := &vssShare{
			Threshold: kg.params.Threshold(),
			ID:        kg.data.ShareID,
			Share:     shareInt,
		}
		if !sh.verify(g, kg.params.Threshold(), vsj) {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("VSS share verification failed for party %s", pid))
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
				sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("aggregating Vc[%d]: %w", c, err))
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
				sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("computing BigXj for party %d: %w", j, err))
				return
			}
			BigXj = next
		}
		kg.data.BigXj[j] = BigXj
	}
	// Identity-element rejection on the joint public key. If every dealer
	// colluded to drive phi_{*,0} to identity (and the per-dealer identity
	// check above were ever loosened), the joint pub would be identity and
	// any "signature" would trivially verify. Reject at finalize as defense
	// in depth. Mirrors frosttss/keygen.go finalize.
	if Vc[0].IsIdentity() {
		sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("frostristretto255tss: joint public key is the group identity"))
		return
	}
	kg.data.GroupPublicKey = Vc[0]
	kg.a_i_0 = nil

	// Ephemeral X25519 private key is no longer needed once decryption
	// completes. Wipe it to defend against process-memory disclosure.
	common.ZeroizeBytes(kg.ephPriv)
	kg.ephPriv = nil

	sendOnce(&kg.doneOnce, kg.Done, kg.data)
}

// buildKeygenSession returns the Session byte string for the round-1 Schnorr
// PoK on a_{i,0}. Bound into the challenge: the FROST ristretto255 context
// string, a "dkg-pok" tag, the party identifier, and a fresh per-keygen
// session nonce broadcast in round 1. The nonce makes the challenge run-unique
// so a PoK cannot be replayed across keygen runs with the same party set.
//
// partyKey is length-prefixed so the (partyKey, sessionNonce) split is
// unambiguous regardless of partyKey byte length. Mirrors
// frosttss/keygen.go buildKeygenSession.
func buildKeygenSession(partyKey *big.Int, sessionNonce []byte) []byte {
	pkBytes := partyKey.Bytes()
	out := make([]byte, 0, len(frost.Ristretto255ContextString)+len("dkg-pok")+1+len(pkBytes)+len(sessionNonce))
	out = append(out, frost.Ristretto255ContextString...)
	out = append(out, []byte("dkg-pok")...)
	out = append(out, byte(len(pkBytes)))
	out = append(out, pkBytes...)
	out = append(out, sessionNonce...)
	return out
}
