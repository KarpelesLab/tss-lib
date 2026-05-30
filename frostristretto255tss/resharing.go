package frostristretto255tss

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frostenc"
	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// buildResharingPoKSession returns the Session byte string for the round-1
// Schnorr PoK on wi. Layout mirrors buildKeygenSession: FROST ristretto255
// context || "reshare-wi-pok" tag || length-prefix(partyKey) || sessionNonce.
// The distinct tag domain-separates from the keygen DKG PoK; the per-reshare
// nonce makes the challenge run-unique. Mirrors
// frosttss/resharing.go buildResharingPoKSession.
func buildResharingPoKSession(partyKey *big.Int, sessionNonce []byte) []byte {
	pkBytes := partyKey.Bytes()
	out := make([]byte, 0, len(frost.Ristretto255ContextString)+len("reshare-wi-pok")+1+len(pkBytes)+len(sessionNonce))
	out = append(out, frost.Ristretto255ContextString...)
	out = append(out, []byte("reshare-wi-pok")...)
	out = append(out, byte(len(pkBytes)))
	out = append(out, pkBytes...)
	out = append(out, sessionNonce...)
	return out
}

// resharingRound3AD constructs the associated-data bytes for the encrypted
// round-3-1 share envelope. Binding (newPartySessionNonce || senderPub ||
// recipientPub) makes the ciphertext non-replayable across (run, sender,
// recipient).
func resharingRound3AD(recipientSessionNonce, senderPub, recipientPub []byte) []byte {
	ad := make([]byte, 0,
		len("frostristretto255tss/reshare/r3/v1|")+
			len(recipientSessionNonce)+len(senderPub)+len(recipientPub)+2)
	ad = append(ad, []byte("frostristretto255tss/reshare/r3/v1|")...)
	ad = append(ad, recipientSessionNonce...)
	ad = append(ad, '|')
	ad = append(ad, senderPub...)
	ad = append(ad, '|')
	ad = append(ad, recipientPub...)
	return ad
}

// Resharing reshares an existing FROST(ristretto255) key from an old
// committee to a new committee, preserving the GroupPublicKey. The protocol
// shape mirrors frosttss/resharing.go with the commitment scheme replaced by
// commitElements (a SHA-512 hash over 32-byte canonical Ristretto255
// encodings rather than the GG18-style FlattenECPoints + cmts).
type Resharing struct {
	ctx    context.Context
	params *tss.ReSharingParameters
	input  *Key

	// Old committee round-1 state.
	wi        *big.Int // Lagrange-weighted local share, retained for the round-1 Schnorr PoK
	newVs     []group.Element
	newShares []*vssShare
	vDecommit []byte // commitElements decommit bytes (kept for round 3 broadcast)

	// Old committee ephemeral X25519 keypair for sealing round-3-1 shares.
	ephPriv []byte
	ephPub  []byte
	// New-committee EphPub / SessionNonce harvested from round-2 ACKs, keyed by
	// new party KeyInt().String(). Used by round3Old to seal each P2P share.
	newEphPubs       map[string][]byte
	newSessionNonces map[string][]byte

	// New committee ephemeral X25519 keypair + session nonce, broadcast in the
	// round-2 ACK so old dealers can seal this party's round-3-1 share.
	myEphPriv      []byte
	myEphPub       []byte
	mySessionNonce []byte

	// New committee round-4 state.
	groupPubKey  group.Element
	round5NewKey *Key

	Done chan *Key
	Err  chan error

	// Once-guards on Done/Err so multi-writer error paths cannot block on
	// the size-1 buffer. See once_send.go for the rationale.
	doneOnce sync.Once
	errOnce  sync.Once
}

// NewResharing starts a FROST(ristretto255) resharing protocol.
func NewResharing(ctx context.Context, params *tss.ReSharingParameters, input *Key) (*Resharing, error) {
	rs := &Resharing{
		ctx:    ctx,
		params: params,
		input:  input,
		Done:   make(chan *Key, 1),
		Err:    make(chan error, 1),
	}
	if params.IsOldCommittee() {
		if err := rs.round1Old(); err != nil {
			return nil, err
		}
	}
	if params.IsNewCommittee() {
		rs.setupNewRound1Receiver()
	}
	return rs, nil
}

func (rs *Resharing) round1Old() error {
	Pi := rs.params.PartyID()
	i := Pi.Index
	g := group.Ristretto255()

	subset, err := rs.input.SubsetForParties(rs.params.OldParties().IDs())
	if err != nil {
		return fmt.Errorf("SubsetForParties: %w", err)
	}
	rs.input = subset

	xi := rs.input.Xi
	ks := rs.input.Ks
	if rs.params.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d not satisfied by key count %d", rs.params.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(g, i, len(rs.params.OldParties().IDs()), xi, ks)

	newKs := rs.params.NewParties().IDs().Keys()
	vi, shares, err := vssCreate(g, rs.params.NewThreshold(), wi, newKs, rs.params.Rand())
	if err != nil {
		return fmt.Errorf("vssCreate: %w", err)
	}

	commit, decommit, err := commitElements(rs.params.Rand(), vi)
	if err != nil {
		return fmt.Errorf("commitElements: %w", err)
	}

	rs.wi = wi // retained for Zeroize on the success / ctx-cancel paths
	rs.newVs = vi
	rs.newShares = shares
	rs.vDecommit = decommit

	// Sample an ephemeral X25519 keypair for sealing round-3-1 shares to the
	// new committee. Public part is sent alongside each ciphertext in round 3.
	ephPriv, ephPub, err := frostenc.NewEphemeralKey(rs.params.Rand())
	if err != nil {
		return fmt.Errorf("frostenc.NewEphemeralKey: %w", err)
	}
	rs.ephPriv = ephPriv
	rs.ephPub = ephPub

	// Schnorr PoK on wi bound to vi[0] = wi*G, plus a fresh per-reshare session
	// nonce. A colluding old coalition cannot covertly rebalance individual wi
	// contributions while keeping the aggregate equal to the master pubkey
	// without producing a valid PoK on the claimed vi[0].
	sessionNonce := make([]byte, resharingSessionNonceLen)
	if _, err := rs.params.Rand().Read(sessionNonce); err != nil {
		return fmt.Errorf("rand for reshare session nonce: %w", err)
	}
	pokSession := buildResharingPoKSession(Pi.KeyInt(), sessionNonce)
	pok, err := schnorrProve(g, pokSession, wi, vi[0], rs.params.Rand())
	if err != nil {
		return fmt.Errorf("schnorrProve on wi: %w", err)
	}

	r1 := &resharingRound1msg{
		GroupPublicKey: rs.input.GroupPublicKey.Bytes(),
		Vi0:            vi[0].Bytes(),
		SessionNonce:   sessionNonce,
		SchnorrR:       pok.R.Bytes(),
		SchnorrT:       g.EncodeScalar(pok.T),
		VCommitment:    commit,
	}

	newParties := rs.params.NewParties().IDs()
	for _, Pj := range newParties {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("frost:ristretto255:reshare:round1", r1, Pi, Pj)
		rs.params.Broker().Receive(m)
	}
	if rs.params.IsNewCommittee() {
		selfMsg := tss.JsonWrap("frost:ristretto255:reshare:round1", r1, Pi, Pi)
		rs.params.Broker().Receive(selfMsg)
	}

	rs.newEphPubs = make(map[string][]byte)
	rs.newSessionNonces = make(map[string][]byte)

	var newOtherIds []*tss.PartyID
	for _, Pj := range newParties {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		newOtherIds = append(newOtherIds, Pj)
	}
	if len(newOtherIds) == 0 {
		go rs.round3Old()
	} else {
		rcv := tss.NewJsonExpect[resharingRound2msg]("frost:ristretto255:reshare:round2", newOtherIds, func(ids []*tss.PartyID, msgs []*resharingRound2msg) {
			if err := rs.harvestNewEphKeys(ids, msgs); err != nil {
				sendOnce(&rs.errOnce, rs.Err, err)
				return
			}
			rs.round3Old()
		})
		rs.params.Broker().Connect("frost:ristretto255:reshare:round2", rcv)
	}
	return nil
}

// harvestNewEphKeys records each new party's round-2 EphPub + SessionNonce so
// round3Old can seal that party's share. Returns an error on malformed input.
func (rs *Resharing) harvestNewEphKeys(ids []*tss.PartyID, msgs []*resharingRound2msg) error {
	for n, pid := range ids {
		msg := msgs[n]
		if len(msg.EphPub) != frostenc.EphemeralKeyBytes {
			return fmt.Errorf("new party %s sent EphPub of length %d (want %d)",
				pid, len(msg.EphPub), frostenc.EphemeralKeyBytes)
		}
		if len(msg.SessionNonce) != resharingSessionNonceLen {
			return fmt.Errorf("new party %s sent session nonce of length %d (want %d)",
				pid, len(msg.SessionNonce), resharingSessionNonceLen)
		}
		rs.newEphPubs[pid.KeyInt().String()] = msg.EphPub
		rs.newSessionNonces[pid.KeyInt().String()] = msg.SessionNonce
	}
	return nil
}

func (rs *Resharing) setupNewRound1Receiver() {
	allOldIds := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds, rs.params.OldParties().IDs())
	rcv := tss.NewJsonExpect[resharingRound1msg]("frost:ristretto255:reshare:round1", allOldIds, func(ids []*tss.PartyID, msgs []*resharingRound1msg) {
		rs.round2New(ids, msgs)
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round1", rcv)
}

func (rs *Resharing) round2New(oldIds []*tss.PartyID, r1msgs []*resharingRound1msg) {
	if rs.ctx.Err() != nil {
		sendOnce(&rs.errOnce, rs.Err, rs.ctx.Err())
		return
	}
	Pi := rs.params.PartyID()
	g := group.Ristretto255()
	N := g.Order()

	// Verify all old parties agree on the GroupPublicKey AND each dealer's
	// Vi0 / Schnorr PoK on wi (FIX 2 — per-dealer integrity).
	var pub group.Element
	for n, msg := range r1msgs {
		pid := oldIds[n]
		candidate, err := g.DecodeElement(msg.GroupPublicKey)
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s sent invalid GroupPublicKey: %w", pid, err),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}
		if pub == nil {
			pub = candidate
		} else if !pub.Equal(candidate) {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s sent inconsistent GroupPublicKey", pid),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}

		// Session nonce + Vi0 length checks.
		if len(msg.SessionNonce) != resharingSessionNonceLen {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s sent session nonce of length %d (want %d)",
					pid, len(msg.SessionNonce), resharingSessionNonceLen),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}
		if len(msg.Vi0) != keygenCommitmentBytes {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s sent Vi0 of length %d (want %d)",
					pid, len(msg.Vi0), keygenCommitmentBytes),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}

		// Decode and identity-reject vi[0].
		vi0, err := g.DecodeElement(msg.Vi0)
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s sent invalid Vi0: %w", pid, err),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}
		if vi0.IsIdentity() {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s round-1 Vi0 is the group identity", pid),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}

		// Verify Schnorr PoK on wi binding to vi0.
		Rj, err := g.DecodeElement(msg.SchnorrR)
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s sent invalid Schnorr R: %w", pid, err),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}
		Tj, err := g.DecodeScalar(msg.SchnorrT)
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s sent invalid Schnorr T: %w", pid, err),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}
		if Tj.Cmp(N) >= 0 {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s Schnorr T not canonical (>= L)", pid),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}
		pokSession := buildResharingPoKSession(pid.KeyInt(), msg.SessionNonce)
		if !schnorrVerify(g, pokSession, vi0, &schnorrProof{R: Rj, T: Tj}) {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s wi PoK verification failed", pid),
				"frost-reshare-round2", 0, nil, pid)))
			return
		}
	}
	rs.groupPubKey = pub

	// Sample this new party's ephemeral X25519 keypair + session nonce so old
	// dealers can seal our round-3-1 share. Broadcast in the round-2 ACK.
	ephPriv, ephPub, err := frostenc.NewEphemeralKey(rs.params.Rand())
	if err != nil {
		sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("frostenc.NewEphemeralKey: %w", err))
		return
	}
	sessionNonce := make([]byte, resharingSessionNonceLen)
	if _, err := rs.params.Rand().Read(sessionNonce); err != nil {
		sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("rand for new-party session nonce: %w", err))
		return
	}
	rs.myEphPriv = ephPriv
	rs.myEphPub = ephPub
	rs.mySessionNonce = sessionNonce

	r2 := &resharingRound2msg{EphPub: ephPub, SessionNonce: sessionNonce}
	for _, Pj := range rs.params.OldParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("frost:ristretto255:reshare:round2", r2, Pi, Pj)
		rs.params.Broker().Receive(m)
	}
	// Dual-membership: if this party is also an old dealer it sends itself a
	// round-3-1 share in round3Old and must find its own new-party EphPub in
	// the harvest map. Seed it here (also a self round-2 message would not be
	// delivered since old parties exclude self above).
	if rs.params.IsOldCommittee() {
		if rs.newEphPubs == nil {
			rs.newEphPubs = make(map[string][]byte)
		}
		if rs.newSessionNonces == nil {
			rs.newSessionNonces = make(map[string][]byte)
		}
		rs.newEphPubs[Pi.KeyInt().String()] = ephPub
		rs.newSessionNonces[Pi.KeyInt().String()] = sessionNonce
	}

	rs.setupNewRound3Receiver(oldIds, r1msgs)
}

func (rs *Resharing) setupNewRound3Receiver(oldIds []*tss.PartyID, r1msgs []*resharingRound1msg) {
	var counter int32
	var r3msg1s []*resharingRound3msg1
	var r3msg1Ids []*tss.PartyID
	var r3msg2s []*resharingRound3msg2
	var r3msg2Ids []*tss.PartyID

	check := func() {
		if atomic.AddInt32(&counter, 1) == 2 {
			rs.round4New(oldIds, r1msgs, r3msg1Ids, r3msg1s, r3msg2Ids, r3msg2s)
		}
	}

	allOldIds := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds, rs.params.OldParties().IDs())

	rcv1 := tss.NewJsonExpect[resharingRound3msg1]("frost:ristretto255:reshare:round3-1", allOldIds, func(ids []*tss.PartyID, msgs []*resharingRound3msg1) {
		r3msg1s = msgs
		r3msg1Ids = ids
		check()
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round3-1", rcv1)

	allOldIds2 := make([]*tss.PartyID, len(rs.params.OldParties().IDs()))
	copy(allOldIds2, rs.params.OldParties().IDs())

	rcv2 := tss.NewJsonExpect[resharingRound3msg2]("frost:ristretto255:reshare:round3-2", allOldIds2, func(ids []*tss.PartyID, msgs []*resharingRound3msg2) {
		r3msg2s = msgs
		r3msg2Ids = ids
		check()
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round3-2", rcv2)
}

func (rs *Resharing) round3Old() {
	if rs.ctx.Err() != nil {
		sendOnce(&rs.errOnce, rs.Err, rs.ctx.Err())
		return
	}
	Pi := rs.params.PartyID()
	g := group.Ristretto255()

	newParties := rs.params.NewParties().IDs()
	for j, Pj := range newParties {
		share := rs.newShares[j]
		// Seal the P2P share under the (rs.ephPriv, new party's EphPub)
		// envelope. The recipient's EphPub + SessionNonce were harvested from
		// the round-2 ACK (or seeded for self on the dual-membership path).
		recipientPub, ok := rs.newEphPubs[Pj.KeyInt().String()]
		if !ok {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("internal: missing new-party EphPub for %s", Pj))
			return
		}
		recipientNonce, ok := rs.newSessionNonces[Pj.KeyInt().String()]
		if !ok {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("internal: missing new-party session nonce for %s", Pj))
			return
		}
		ad := resharingRound3AD(recipientNonce, rs.ephPub, recipientPub)
		plaintext := g.EncodeScalar(share.Share)
		ct, err := frostenc.SealShare(rs.params.Rand(), rs.ephPriv, recipientPub, ad, plaintext)
		for i := range plaintext {
			plaintext[i] = 0
		}
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("seal reshare share to %s: %w", Pj, err))
			return
		}
		r3m1 := &resharingRound3msg1{EphPub: rs.ephPub, Ciphertext: ct}
		m := tss.JsonWrap("frost:ristretto255:reshare:round3-1", r3m1, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	// vDecommit splits into 32-byte chunks: randomness (1 chunk) + threshold+1 element chunks
	chunks := make([][]byte, 0, (len(rs.vDecommit) / 32))
	for k := 0; k < len(rs.vDecommit); k += 32 {
		chunks = append(chunks, rs.vDecommit[k:k+32])
	}
	r3m2 := &resharingRound3msg2{VDecommitment: chunks}
	for _, Pj := range newParties {
		m := tss.JsonWrap("frost:ristretto255:reshare:round3-2", r3m2, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	rs.setupOldRound4Receiver()
}

func (rs *Resharing) setupOldRound4Receiver() {
	Pi := rs.params.PartyID()
	var otherNewIds []*tss.PartyID
	for _, Pj := range rs.params.NewParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		otherNewIds = append(otherNewIds, Pj)
	}
	if len(otherNewIds) == 0 {
		go rs.round5Old()
		return
	}
	rcv := tss.NewJsonExpect[resharingRound4msg]("frost:ristretto255:reshare:round4", otherNewIds, func(_ []*tss.PartyID, _ []*resharingRound4msg) {
		rs.round5Old()
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round4", rcv)
}

func (rs *Resharing) round4New(
	oldIds []*tss.PartyID,
	r1msgs []*resharingRound1msg,
	r3msg1Ids []*tss.PartyID,
	r3msg1s []*resharingRound3msg1,
	r3msg2Ids []*tss.PartyID,
	r3msg2s []*resharingRound3msg2,
) {
	if rs.ctx.Err() != nil {
		sendOnce(&rs.errOnce, rs.Err, rs.ctx.Err())
		return
	}
	Pi := rs.params.PartyID()
	g := group.Ristretto255()
	allOldIds := rs.params.OldParties().IDs()

	oldKeyToIdx := make(map[string]int)
	for idx, p := range allOldIds {
		oldKeyToIdx[p.KeyInt().String()] = idx
	}
	r1ByOldIdx := make(map[int]*resharingRound1msg)
	for n, pid := range oldIds {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r1ByOldIdx[idx] = r1msgs[n]
		}
	}
	r3m1ByOldIdx := make(map[int]*resharingRound3msg1)
	for n, pid := range r3msg1Ids {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r3m1ByOldIdx[idx] = r3msg1s[n]
		}
	}
	r3m2ByOldIdx := make(map[int]*resharingRound3msg2)
	for n, pid := range r3msg2Ids {
		if idx, ok := oldKeyToIdx[pid.KeyInt().String()]; ok {
			r3m2ByOldIdx[idx] = r3msg2s[n]
		}
	}

	newXi := big.NewInt(0)
	modQ := common.ModInt(g.Order())
	vjc := make([][]group.Element, len(allOldIds))

	for j := 0; j < len(allOldIds); j++ {
		r1msg, ok := r1ByOldIdx[j]
		if !ok {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("missing round1 message from old party %d", j))
			return
		}
		r3msg1, ok := r3m1ByOldIdx[j]
		if !ok {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("missing round3-1 message from old party %d", j))
			return
		}
		r3msg2, ok := r3m2ByOldIdx[j]
		if !ok {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("missing round3-2 message from old party %d", j))
			return
		}

		// Reassemble decommit bytes and verify against the commit.
		decommit := make([]byte, 0, 32*(rs.params.NewThreshold()+2))
		for _, chunk := range r3msg2.VDecommitment {
			decommit = append(decommit, chunk...)
		}
		ok2, vj, err := verifyCommitElements(g, r1msg.VCommitment, decommit, rs.params.NewThreshold()+1)
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("decommit decode for old party %d: %w", j, err))
			return
		}
		if !ok2 {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("commit verify failed for old party %d", j))
			return
		}

		// Per-dealer equivocation cross-check (FIX 2): the round-1 Vi0
		// (already PoK-verified in round2New) must match the vi[0]
		// reconstructed from the round-3 decommitment. A mismatch is dealer
		// equivocation between round 1 and round 3 — a coalition that signed
		// the PoK on one wi but then opened a different vi[0] to skew the
		// share derivation.
		pid := allOldIds[j]
		round1Vi0, err := g.DecodeElement(r1msg.Vi0)
		if err != nil || !round1Vi0.Equal(vj[0]) {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s round-1 Vi0 disagrees with round-3 vi[0] (equivocation)", pid),
				"frost-reshare-round4", 0, nil, pid)))
			return
		}
		vjc[j] = vj

		// Decrypt the P2P share sealed by the old dealer.
		if len(r3msg1.EphPub) != frostenc.EphemeralKeyBytes {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s sent EphPub of length %d (want %d)",
					pid, len(r3msg1.EphPub), frostenc.EphemeralKeyBytes),
				"frost-reshare-round4", 0, nil, pid)))
			return
		}
		ad := resharingRound3AD(rs.mySessionNonce, r3msg1.EphPub, rs.myEphPub)
		shareBytes, err := frostenc.OpenShare(rs.myEphPriv, r3msg1.EphPub, ad, r3msg1.Ciphertext)
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, error(tss.NewError(
				fmt.Errorf("party %s share ciphertext failed to open: %w", pid, err),
				"frost-reshare-round4", 0, nil, pid)))
			return
		}
		shareInt, err := g.DecodeScalar(shareBytes)
		for i := range shareBytes {
			shareBytes[i] = 0
		}
		if err != nil {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("invalid share scalar from old party %d: %w", j, err))
			return
		}
		sharej := &vssShare{
			Threshold: rs.params.NewThreshold(),
			ID:        Pi.KeyInt(),
			Share:     shareInt,
		}
		if !sharej.verify(g, rs.params.NewThreshold(), vj) {
			sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("VSS share verification failed for old party %d", j))
			return
		}
		newXi = new(big.Int).Add(newXi, sharej.Share)
	}

	// Aggregate Vc and verify Vc[0] == groupPubKey.
	Vc := make([]group.Element, rs.params.NewThreshold()+1)
	for c := 0; c <= rs.params.NewThreshold(); c++ {
		Vc[c] = vjc[0][c].Clone()
		for j := 1; j < len(vjc); j++ {
			sum, err := Vc[c].Add(vjc[j][c])
			if err != nil {
				sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("Vc[%d] aggregate: %w", c, err))
				return
			}
			Vc[c] = sum
		}
	}
	if !Vc[0].Equal(rs.groupPubKey) {
		sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("assertion failed: V_0 != GroupPublicKey"))
		return
	}

	newKs := make([]*big.Int, 0, rs.params.NewPartyCount())
	newBigXjs := make([]group.Element, rs.params.NewPartyCount())
	for j := 0; j < rs.params.NewPartyCount(); j++ {
		Pj := rs.params.NewParties().IDs()[j]
		kj := Pj.KeyInt()
		newKs = append(newKs, kj)
		newBigXj := Vc[0].Clone()
		z := big.NewInt(1)
		for c := 1; c <= rs.params.NewThreshold(); c++ {
			z = modQ.Mul(z, kj)
			next, err := newBigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				sendOnce(&rs.errOnce, rs.Err, fmt.Errorf("computing newBigXj: %w", err))
				return
			}
			newBigXj = next
		}
		newBigXjs[j] = newBigXj
	}

	newXi = new(big.Int).Mod(newXi, g.Order())
	newKey := NewKey(rs.params.NewPartyCount())
	newKey.Xi = newXi
	newKey.ShareID = Pi.KeyInt()
	newKey.Ks = newKs
	newKey.BigXj = newBigXjs
	newKey.GroupPublicKey = rs.groupPubKey
	rs.round5NewKey = newKey

	r4 := &resharingRound4msg{}
	for _, Pj := range rs.params.OldAndNewParties() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		m := tss.JsonWrap("frost:ristretto255:reshare:round4", r4, Pi, Pj)
		rs.params.Broker().Receive(m)
	}

	if rs.params.IsOldCommittee() {
		return
	}

	var otherNewIds []*tss.PartyID
	for _, Pj := range rs.params.NewParties().IDs() {
		if Pj.KeyInt().Cmp(Pi.KeyInt()) == 0 {
			continue
		}
		otherNewIds = append(otherNewIds, Pj)
	}
	if len(otherNewIds) == 0 {
		sendOnce(&rs.doneOnce, rs.Done, newKey)
		return
	}
	rcv := tss.NewJsonExpect[resharingRound4msg]("frost:ristretto255:reshare:round4", otherNewIds, func(_ []*tss.PartyID, _ []*resharingRound4msg) {
		sendOnce(&rs.doneOnce, rs.Done, newKey)
	})
	rs.params.Broker().Connect("frost:ristretto255:reshare:round4", rcv)
}

func (rs *Resharing) round5Old() {
	// Zeroize BEFORE the ctx-err early return. An attacker racing a ctx cancel
	// after round 3 (when shares are already on the wire) would otherwise leave
	// the old Xi/wi resident on the heap while the new committee already
	// possesses the resharing data — defeating the proactive-security claim.
	if rs.input != nil {
		common.ZeroizeBigInt(rs.input.Xi)
	}
	common.ZeroizeBigInt(rs.wi)
	rs.wi = nil
	common.ZeroizeBytes(rs.ephPriv)
	rs.ephPriv = nil

	if rs.ctx.Err() != nil {
		sendOnce(&rs.errOnce, rs.Err, rs.ctx.Err())
		return
	}
	if rs.params.IsNewCommittee() && rs.round5NewKey != nil {
		sendOnce(&rs.doneOnce, rs.Done, rs.round5NewKey)
	} else {
		sendOnce(&rs.doneOnce, rs.Done, nil)
	}
}
