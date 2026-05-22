package frosttss

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frostenc"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Keygen tracks a key currently being generated via the FROST Pedersen DKG
// (Komlo–Goldberg, IACR eprint 2020/852). Note: RFC 9591 places DKG outside
// the body of the RFC ("dealerless DKGs are out of scope of this document",
// §5); the Pedersen DKG described in the FROST paper is the de facto
// reference implemented here.
type Keygen struct {
	ctx    context.Context
	params *tss.Parameters
	vs     vss.Vs     // local polynomial commitments (Feldman)
	shares vss.Shares // local shares for every party
	a_i_0  *big.Int   // local secret coefficient — retained for the round-1 Schnorr PoK
	data   *Key

	// Ephemeral X25519 keypair for the round-2 encrypted-share envelope.
	// Sampled fresh per keygen run. ephPriv is zeroized at finalize.
	ephPriv []byte
	ephPub  []byte
	// peerEphPubs maps each peer's KeyInt().String() to their broadcast
	// EphPub from round 1, so round 2 can look up the recipient key.
	peerEphPubs map[string][]byte
	// peerSessionNonces parallel to peerEphPubs: per-peer SessionNonce
	// for AD reconstruction in finalize.
	peerSessionNonces map[string][]byte
	// mySessionNonce stores the local SessionNonce broadcast in round 1
	// so round 2 can include it in the associated-data binding.
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
// recipientPub || tag) makes the ciphertext non-replayable across
// (run, sender, recipient, label).
func keygenRound2AD(senderSessionNonce, senderPub, recipientPub []byte) []byte {
	ad := make([]byte, 0,
		len("frosttss/keygen/r2/v1|")+
			len(senderSessionNonce)+
			len(senderPub)+
			len(recipientPub)+3)
	ad = append(ad, []byte("frosttss/keygen/r2/v1|")...)
	ad = append(ad, senderSessionNonce...)
	ad = append(ad, '|')
	ad = append(ad, senderPub...)
	ad = append(ad, '|')
	ad = append(ad, recipientPub...)
	return ad
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

	// Sample a fresh 16-byte session nonce. The nonce is broadcast alongside
	// the commitments so receivers can verify the PoK against it. This
	// breaks PoK replay across keygen runs (an attacker re-injecting a
	// previously-observed round-1 from the same party would carry an old
	// nonce and would not match the verifier's freshly-sampled one — but
	// more importantly, no fresh DKG would ever produce the same nonce so
	// the verifier of the replayed message would reject when the dealer
	// supposedly re-derives the same a_{i,0}: see TestKeygenSessionNonceDiffers).
	sessionNonce := make([]byte, keygenSessionNonceLen)
	if _, err := kg.params.Rand().Read(sessionNonce); err != nil {
		return fmt.Errorf("rand for session nonce: %w", err)
	}

	// Sample a fresh ephemeral X25519 keypair. The public component is
	// broadcast in round 1 and used by every other party to derive a
	// per-pair AEAD key for the encrypted round-2 P2P share envelope.
	// Without this, round-2 shares would be sent in cleartext and a
	// passive eavesdropper plus t-1 corrupted parties could recover the
	// master secret.
	ephPriv, ephPub, err := frostenc.NewEphemeralKey(kg.params.Rand())
	if err != nil {
		return fmt.Errorf("frostenc.NewEphemeralKey: %w", err)
	}
	kg.ephPriv = ephPriv
	kg.ephPub = ephPub
	kg.mySessionNonce = sessionNonce

	// Schnorr PoK of a_{i,0} bound to phi_{i,0} = vs[0]. The Session string
	// encodes the FROST context, the party's identifier, AND the per-keygen
	// session nonce so cross-party PoK substitution and cross-keygen PoK
	// replay attacks are both impossible.
	//
	// Note: crypto/schnorr.NewZKProof uses a different challenge hash than
	// the Komlo-Goldberg paper's compute_proof_of_knowledge (it's the GG18
	// form already audited in this repo). The proof is still a valid Schnorr
	// PoK of the same statement; we are not aiming for byte-level test-vector
	// compatibility for this internal PoK.
	session := buildKeygenSession(ids[i], sessionNonce)
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
		SessionNonce:       sessionNonce,
		EphPub:             ephPub,
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
	N := ec.Params().N
	peerVs := make([]vss.Vs, len(otherIds))
	kg.peerEphPubs = make(map[string][]byte, len(otherIds))
	kg.peerSessionNonces = make(map[string][]byte, len(otherIds))
	for n, pid := range otherIds {
		r1 := r1msgs[n]
		if len(r1.PolyCommitments) != kg.params.Threshold()+1 {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s sent %d commitments, expected %d",
					pid, len(r1.PolyCommitments), kg.params.Threshold()+1),
				"frost-keygen-round2", 0, nil, pid)))
			return
		}
		// Length cap on each commitment to bound parse work.
		for k, enc := range r1.PolyCommitments {
			if len(enc) != keygenCommitmentBytes {
				sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
					fmt.Errorf("party %s commitment[%d] has wrong length %d (want %d)",
						pid, k, len(enc), keygenCommitmentBytes),
					"frost-keygen-round2", 0, nil, pid)))
				return
			}
		}
		// Session nonce length check — we accept any non-empty nonce of the
		// expected length. Empty / wrong-length is a protocol violation.
		if len(r1.SessionNonce) != keygenSessionNonceLen {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s sent session nonce of length %d (want %d)",
					pid, len(r1.SessionNonce), keygenSessionNonceLen),
				"frost-keygen-round2", 0, nil, pid)))
			return
		}
		// EphPub length check.
		if len(r1.EphPub) != frostenc.EphemeralKeyBytes {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s sent EphPub of length %d (want %d)",
					pid, len(r1.EphPub), frostenc.EphemeralKeyBytes),
				"frost-keygen-round2", 0, nil, pid)))
			return
		}
		kg.peerEphPubs[pid.KeyInt().String()] = r1.EphPub
		kg.peerSessionNonces[pid.KeyInt().String()] = r1.SessionNonce
		// Length caps on Schnorr proof fields (32-byte Ed25519 scalars and
		// 32-byte coordinates).
		if len(r1.SchnorrProofAlphaX) > keygenCommitmentBytes ||
			len(r1.SchnorrProofAlphaY) > keygenCommitmentBytes ||
			len(r1.SchnorrProofT) > keygenScalarBytes {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s sent oversize Schnorr proof field", pid),
				"frost-keygen-round2", 0, nil, pid)))
			return
		}

		vsj := make(vss.Vs, len(r1.PolyCommitments))
		for k, enc := range r1.PolyCommitments {
			p, err := frost.DecodeElement(enc)
			if err != nil {
				sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
					fmt.Errorf("party %s sent invalid poly commitment %d: %w", pid, k, err),
					"frost-keygen-round2", 0, nil, pid)))
				return
			}
			// Cofactor-clear received points so any malicious-but-on-curve point
			// is projected into the prime-order subgroup. Legitimate points are
			// already in the subgroup so this is a no-op for honest senders.
			vsj[k] = p.EightInvEight()
		}
		// Identity-element rejection: a dealer that publishes phi_{j,0} =
		// identity contributes zero to the joint secret. The cofactor-clear
		// above maps any small-subgroup contribution into the prime-order
		// subgroup, which includes the identity. The Schnorr PoK on the
		// constant coefficient passes with witness 0, so without this
		// explicit check a colluding dealer can effectively skip its
		// contribution to the joint key. Reject every dealer's phi_{j,0}
		// that resolves to the identity.
		if vsj[0].IsIdentity() {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s round-1 phi_{j,0} is the curve identity (rogue-zero contribution)", pid),
				"frost-keygen-round2", 0, nil, pid)))
			return
		}
		peerVs[n] = vsj

		// Verify Schnorr PoK on the constant coefficient phi_{j,0} = vsj[0],
		// using the peer's broadcast session nonce. Distinct nonces produce
		// distinct challenges; an attacker cannot replay an old PoK because
		// the old broadcast carried an old nonce that the peer would not
		// have re-derived.
		session := buildKeygenSession(pid.KeyInt(), r1.SessionNonce)
		alphaX := new(big.Int).SetBytes(r1.SchnorrProofAlphaX)
		alphaY := new(big.Int).SetBytes(r1.SchnorrProofAlphaY)
		alpha, err := crypto.NewECPoint(ec, alphaX, alphaY)
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s sent invalid Schnorr alpha: %w", pid, err),
				"frost-keygen-round2", 0, nil, pid)))
			return
		}
		// Range-check the response scalar T: must be in [0, L). The wire
		// format allows non-canonical encodings (e.g., T + k·L); reject
		// those to keep the proof's wire serialization unique.
		tScalar := new(big.Int).SetBytes(r1.SchnorrProofT)
		if tScalar.Cmp(N) >= 0 {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s Schnorr T not canonical (>= L)", pid),
				"frost-keygen-round2", 0, nil, pid)))
			return
		}
		pok := &schnorr.ZKProof{Alpha: alpha, T: tScalar}
		if !pok.Verify(session, vsj[0]) {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s Schnorr PoK verification failed", pid),
				"frost-keygen-round2", 0, nil, pid)))
			return
		}
	}

	// Send each other party their P2P share. The share for party j is
	// f_i(x_j) — stored in kg.shares with ID == x_j. Encrypted under
	// the (kg.ephPriv, peer's EphPub) X25519+ChaCha20-Poly1305 envelope
	// so a passive eavesdropper on the broker cannot recover the share.
	mySessionNonce, err := kg.findMySessionNonce()
	if err != nil {
		sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("internal: %w", err))
		return
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
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("internal: missing share for party %s", Pj))
			return
		}
		recipientPub, ok := kg.peerEphPubs[Pj.KeyInt().String()]
		if !ok {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("internal: missing peer EphPub for %s", Pj))
			return
		}
		ad := keygenRound2AD(mySessionNonce, kg.ephPub, recipientPub)
		plaintext := shareForPj.Bytes()
		ct, err := frostenc.SealShare(kg.params.Rand(), kg.ephPriv, recipientPub, ad, plaintext)
		// Best-effort zeroize the plaintext copy on this goroutine
		// stack; the original kg.shares[*].Share is left for the
		// post-finalize zeroize path.
		for i := range plaintext {
			plaintext[i] = 0
		}
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("seal share to %s: %w", Pj, err))
			return
		}
		r2 := &keygenRound2msg{Ciphertext: ct}
		m := tss.JsonWrap("frost:ed25519:keygen:round2", r2, Pi, Pj)
		kg.params.Broker().Receive(m)
	}

	// Register receiver for round 2 P2P shares from all others.
	rcv := tss.NewJsonExpect[keygenRound2msg]("frost:ed25519:keygen:round2", otherIds, func(ids []*tss.PartyID, msgs []*keygenRound2msg) {
		kg.finalize(otherIds, peerVs, ids, msgs)
	})
	kg.params.Broker().Connect("frost:ed25519:keygen:round2", rcv)
}

// findMySessionNonce returns the local party's own SessionNonce that was
// broadcast in round 1. Stored on the struct at round1-time so round 2
// can include it in the AD for the encrypted share envelope.
func (kg *Keygen) findMySessionNonce() ([]byte, error) {
	if len(kg.mySessionNonce) != keygenSessionNonceLen {
		return nil, fmt.Errorf("session nonce missing or wrong length")
	}
	return kg.mySessionNonce, nil
}

// peerSessionNonceByID returns the SessionNonce that peer pid broadcast
// in round 1 (or ok==false if the peer was not in round 1 — should not
// happen in well-formed protocol flow).
func (kg *Keygen) peerSessionNonceByID(pid *tss.PartyID) ([]byte, bool) {
	nonce, ok := kg.peerSessionNonces[pid.KeyInt().String()]
	return nonce, ok
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

	_ = r1Ids // peerSessionNonces / peerEphPubs lookups index by KeyInt.

	// Verify each P2P share against its sender's Feldman commitments and
	// accumulate into our Xi.
	xi := new(big.Int).Set(kg.shares[PIdx].Share)
	for n, pid := range r2Ids {
		vsj, ok := vsByID[pid.KeyInt().String()]
		if !ok {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("share from party %s had no matching round-1 commitments", pid))
			return
		}
		// Decrypt the share. AD is reconstructed from the sender's
		// SessionNonce (= sender's peerSessionNonce snapshot in round
		// 2). Since we don't carry that through to finalize, we look
		// up via the sessionNonce map keyed by pid.
		senderSessionNonce, ok := kg.peerSessionNonceByID(pid)
		if !ok {
			sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("share from %s: missing peer session nonce", pid))
			return
		}
		senderPub := kg.peerEphPubs[pid.KeyInt().String()]
		ad := keygenRound2AD(senderSessionNonce, senderPub, kg.ephPub)
		shareBytes, err := frostenc.OpenShare(kg.ephPriv, senderPub, ad, r2msgs[n].Ciphertext)
		if err != nil {
			sendOnce(&kg.errOnce, kg.Err, error(tss.NewError(
				fmt.Errorf("party %s share ciphertext failed to open: %w", pid, err),
				"frost-keygen-finalize", 0, nil, pid)))
			return
		}
		shareInt := new(big.Int).SetBytes(shareBytes)
		// Best-effort zeroize the plaintext bytes immediately.
		for i := range shareBytes {
			shareBytes[i] = 0
		}
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
	// Identity-element rejection on the joint public key. If every dealer
	// colluded to publish phi_{*,0}=identity (and the per-dealer identity
	// check above somehow passed for all — it should not, since that check
	// rejects each dealer's identity contribution individually — or if a
	// future change ever loosens the per-dealer check), the joint pub
	// would be identity and any "signature" trivially "verifies". Reject
	// at finalize as defense in depth.
	if pub.IsIdentity() {
		sendOnce(&kg.errOnce, kg.Err, fmt.Errorf("frosttss: joint public key is the curve identity"))
		return
	}
	kg.data.GroupPublicKey = pub
	// Master chain code = SHA-256(domain || EncodeElement(pub)).
	// Deterministic from the joint pubkey, so every party computes the
	// same value with no extra communication. Enables non-hardened HD
	// derivation via Key.DeriveChild.
	kg.data.ChainCode = DeriveChainCode(pub)

	// a_i_0 is no longer needed; scrub it before returning. Best-effort
	// (Go GC may have copied), but at minimum we don't pin a long-lived
	// reference to the dealer's secret coefficient.
	common.ZeroizeBigInt(kg.a_i_0)
	kg.a_i_0 = nil

	// Ephemeral X25519 private key is no longer needed once decryption
	// completes. Wipe it to defend against process-memory disclosure.
	common.ZeroizeBytes(kg.ephPriv)
	kg.ephPriv = nil

	sendOnce(&kg.doneOnce, kg.Done, kg.data)
}

// buildKeygenSession returns a fixed-format Session byte string for the
// Schnorr PoK on a_i,0 in DKG round 1.
//
// Bound into the challenge:
//   - frost.ContextString — domain-separates from other FROST hashes.
//   - "dkg-pok" tag — domain-separates from other Schnorr proofs in the
//     repo (e.g., DKLs23, identity-key proofs).
//   - partyKey — the dealer's identifier; prevents cross-party PoK
//     substitution.
//   - sessionNonce — a fresh per-keygen 16-byte CSPRNG value broadcast in
//     the dealer's round-1 message; prevents PoK replay across keygen
//     runs. Two DKG runs with the same party set produce different
//     challenges because the nonce is fresh per call.
//
// A length prefix separates partyKey from sessionNonce so the
// concatenation is injective for any input pair.
func buildKeygenSession(partyKey *big.Int, sessionNonce []byte) []byte {
	pkBytes := partyKey.Bytes()
	out := make([]byte, 0, len(frost.ContextString)+len("dkg-pok")+1+len(pkBytes)+len(sessionNonce))
	out = append(out, frost.ContextString...)
	out = append(out, []byte("dkg-pok")...)
	// Length-prefix partyKey to make the (partyKey, sessionNonce) split
	// unambiguous regardless of partyKey byte length.
	out = append(out, byte(len(pkBytes)))
	out = append(out, pkBytes...)
	out = append(out, sessionNonce...)
	return out
}
