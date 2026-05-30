package mldsatss

import (
	"context"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/KarpelesLab/mldsa"
	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// zeroizeFVec44 best-effort wipes a hyperball sample (secret nonce y) by
// overwriting every float64 lane with zero. Like common.ZeroizeBytes, this is
// best-effort: Go's GC may already have copied the value elsewhere.
func zeroizeFVec44(fv *mldsa.FVec44) {
	for i := range fv {
		fv[i] = 0
	}
}

// zeroizeNttVecL44 / zeroizeNttVecK44 wipe recovered secret NTT vectors.
func zeroizeNttVecL44(v *[mldsa.L44]mldsa.NttElement) {
	for i := range v {
		for j := range v[i] {
			v[i][j] = 0
		}
	}
}

func zeroizeNttVecK44(v *[mldsa.K44]mldsa.NttElement) {
	for i := range v {
		for j := range v[i] {
			v[i][j] = 0
		}
	}
}

// ErrAllTriesRejected is returned when every one of the K parallel tries in a
// single 3-round signing exchange is rejected (by party-side bound or
// Combine-side correctness). Callers should retry with a fresh attempt.
var ErrAllTriesRejected = errors.New("mldsatss: all tries rejected; retry")

// Parameters bundles the session configuration for a threshold ML-DSA-44
// signing run.
type Parameters struct {
	partyID   *tss.PartyID
	parties   *tss.PeerContext // sorted signing committee (length == T)
	thParams  *ThresholdParams44
	keyIds    []uint8 // keyIds[i] = Key44.Id of parties.IDs()[i]
	attemptID uint32  // unique id within a broker; appended to message type names
	broker    tss.MessageBroker
	rand      io.Reader
}

// NewParameters builds a Parameters value. parties must be the sorted
// signing committee (length equal to thParams.T), keyIds must be the
// Key44.Id of each party in the same order.
func NewParameters(
	partyID *tss.PartyID,
	parties *tss.PeerContext,
	thParams *ThresholdParams44,
	keyIds []uint8,
	broker tss.MessageBroker,
) (*Parameters, error) {
	if thParams == nil {
		return nil, errors.New("mldsatss: thParams must not be nil")
	}
	if len(parties.IDs()) != int(thParams.T) {
		return nil, fmt.Errorf("mldsatss: signing committee must have %d members, got %d",
			thParams.T, len(parties.IDs()))
	}
	if len(keyIds) != int(thParams.T) {
		return nil, fmt.Errorf("mldsatss: keyIds must have %d entries, got %d",
			thParams.T, len(keyIds))
	}
	// Correctness requires keyIds[i] to be the Key44.Id of parties.IDs()[i],
	// where parties.IDs() is the canonical (sorted) committee ordering. The
	// committee slot used in signing is derived from this sorted order, so a
	// misaligned keyIds slice would silently bind the wrong share/keyId to a
	// party. We cannot recover each party's true Id from its PartyID here, but
	// the canonical convention assigns ascending Ids to the ascending-sorted
	// parties; enforce that keyIds is strictly increasing (and therefore
	// distinct), matching the sorted parties.IDs() ordering.
	ids := parties.IDs()
	for i := 0; i < len(keyIds); i++ {
		if i > 0 && keyIds[i] <= keyIds[i-1] {
			return nil, fmt.Errorf(
				"mldsatss: keyIds must be strictly increasing to match the sorted "+
					"committee ordering; keyIds[%d]=%d is not greater than keyIds[%d]=%d",
				i, keyIds[i], i-1, keyIds[i-1])
		}
		_ = ids[i] // length already checked equal to len(keyIds)
	}
	return &Parameters{
		partyID:  partyID,
		parties:  parties,
		thParams: thParams,
		keyIds:   append([]uint8(nil), keyIds...),
		broker:   broker,
		rand:     rand.Reader,
	}, nil
}

// SetRand overrides the randomness source (defaults to crypto/rand.Reader).
func (p *Parameters) SetRand(r io.Reader) { p.rand = r }

// SetAttemptID sets a per-session id that is appended to the message type
// strings, so that multiple attempts on the same broker do not collide.
func (p *Parameters) SetAttemptID(id uint32) { p.attemptID = id }

func (p *Parameters) msgType(base string) string {
	return fmt.Sprintf("%s#%d", base, p.attemptID)
}

// Signing44 drives the 3-round threshold ML-DSA-44 signing protocol for one
// attempt. If all K tries are rejected, Signing44 signals ErrAllTriesRejected
// via Err; callers can retry by creating a new Signing44 with a fresh
// attempt id.
type Signing44 struct {
	ctx    context.Context
	params *Parameters
	key    *Key44
	msg    []byte
	msgCtx []byte
	myRank uint8 // position of this party within the signing committee
	act    uint8 // bitmask over Key44.Ids of the signing committee

	// Round-1 state kept across rounds:
	wVecs [][mldsa.K44]mldsa.RingElement // (K tries) × K44 polys — raw w_i = A r_i + e_i
	stws  []mldsa.FVec44                 // K hyperball samples (state for ComputeResponses)
	wbuf  []byte                         // packed w's for this party, broadcast in round 2

	// Round-2 state:
	mu [64]byte // CRH(Tr || 0 || ctxlen || ctx || msg)

	// Pending counters for two parallel receives in round 1 (kept simple: 1
	// counter that reaches zero when all round-1 commitments are in).
	r1commits [][]byte // 32-byte commitments indexed by committee slot (ourselves included)

	// Round-2 reveals, indexed by committee slot:
	r2wbufs [][]byte

	// Round-3 responses, indexed by committee slot:
	r3resps [][]byte

	// Number of messages still expected per phase (atomic).
	pending2 int32
	pending3 int32

	Done chan *SignatureData
	Err  chan error
}

// NewSigning44 starts a threshold ML-DSA-44 signing session. It registers
// round-1/2/3 receivers on the params.Broker and immediately broadcasts the
// party's Round 1 commitment.
//
// The returned Signing44 emits the final signature on Done, or an error on
// Err. If every try in this attempt is rejected, Err receives
// ErrAllTriesRejected; the caller should retry with a new attempt id.
func NewSigning44(ctx context.Context, params *Parameters, key *Key44, msg, msgCtx []byte) (*Signing44, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if len(msgCtx) > 255 {
		return nil, errors.New("mldsatss: context longer than 255 bytes")
	}

	// Locate our rank within the committee + build act mask.
	myRank := -1
	act := uint8(0)
	for i, kid := range params.keyIds {
		act |= 1 << kid
		if kid == key.Id {
			myRank = i
		}
	}
	if myRank < 0 {
		return nil, errors.New("mldsatss: this key is not in the signing committee")
	}

	s := &Signing44{
		ctx:       ctx,
		params:    params,
		key:       key,
		msg:       append([]byte(nil), msg...),
		msgCtx:    append([]byte(nil), msgCtx...),
		myRank:    uint8(myRank),
		act:       act,
		r1commits: make([][]byte, params.thParams.T),
		r2wbufs:   make([][]byte, params.thParams.T),
		r3resps:   make([][]byte, params.thParams.T),
		Done:      make(chan *SignatureData, 1),
		Err:       make(chan error, 1),
	}

	// Round 1 both broadcasts and installs its own receiver (the latter after
	// broadcast, so other parties' messages can be queued in the interim).
	if err := s.round1(); err != nil {
		return nil, err
	}
	return s, nil
}

// otherPartyIDs returns the committee excluding this party.
func (s *Signing44) otherPartyIDs() []*tss.PartyID {
	all := s.params.parties.IDs()
	out := make([]*tss.PartyID, 0, len(all)-1)
	selfKey := s.params.partyID.KeyInt()
	for _, pid := range all {
		if pid.KeyInt().Cmp(selfKey) == 0 {
			continue
		}
		out = append(out, pid)
	}
	return out
}

// round1 samples this party's K hyperball vectors, computes w_i = A·r_i + e_i
// for each, packs them and broadcasts the hash commitment.
func (s *Signing44) round1() error {
	params := s.params.thParams
	kTries := int(params.K)

	// Fresh rhop from the party's RNG. It seeds every hyperball sample for
	// this attempt, so wipe it as soon as round1 returns (the per-try secret
	// nonces y derived from it live on in s.stws until round3).
	var rhop [64]byte
	if _, err := io.ReadFull(s.params.rand, rhop[:]); err != nil {
		return fmt.Errorf("mldsatss: rhop read failed: %w", err)
	}
	defer common.ZeroizeBytes(rhop[:])

	// Cached matrix A (NTT form, row-major K44×L44).
	A := s.key.Matrix()

	s.wVecs = make([][mldsa.K44]mldsa.RingElement, kTries)
	s.stws = make([]mldsa.FVec44, kTries)

	for tryIdx := 0; tryIdx < kTries; tryIdx++ {
		// Sample a hyperball point; split into (r, e_) via Round.
		var fv mldsa.FVec44
		mldsa.SampleHyperball44(&fv, params.Rp, params.Nu, rhop, uint16(tryIdx))
		s.stws[tryIdx] = fv

		var r [mldsa.L44]mldsa.RingElement
		var eK [mldsa.K44]mldsa.RingElement
		fv.Round(r[:], eK[:])

		// rNTT = NTT(r)
		var rh [mldsa.L44]mldsa.NttElement
		for i := 0; i < mldsa.L44; i++ {
			rh[i] = mldsa.NTT(r[i])
		}

		// w_i = A·rNTT + eK
		for i := 0; i < mldsa.K44; i++ {
			var acc mldsa.NttElement
			for j := 0; j < mldsa.L44; j++ {
				acc = mldsa.PolyAdd(acc, mldsa.NttMul(A[i*mldsa.L44+j], rh[j]))
			}
			s.wVecs[tryIdx][i] = mldsa.PolyAdd(mldsa.InvNTT(acc), eK[i])
		}
	}

	// Pack all w vectors into wbuf (one 23-bit poly per K44×K-try cell).
	s.wbuf = make([]byte, kTries*mldsa.K44*mldsa.PackPolyQSize)
	off := 0
	for tryIdx := 0; tryIdx < kTries; tryIdx++ {
		for i := 0; i < mldsa.K44; i++ {
			mldsa.PackPolyQ(s.wVecs[tryIdx][i], s.wbuf[off:off+mldsa.PackPolyQSize])
			off += mldsa.PackPolyQSize
		}
	}

	// Commitment: SHAKE256(Tr || keyId || wbuf) → 32 bytes.
	commit := s.computeCommitment(s.key.Id, s.wbuf)
	s.r1commits[s.myRank] = commit

	// Broadcast the commitment first — other parties' brokers will queue it
	// until their receivers register, so wbuf is guaranteed to be in place.
	msg := &signRound1msg44{Commit: commit}
	others := s.otherPartyIDs()
	for _, pj := range others {
		if err := s.params.broker.Receive(tss.JsonWrap(
			s.params.msgType(MsgTypeR1_44), msg, s.params.partyID, pj,
		)); err != nil {
			return fmt.Errorf("mldsatss: round1 broadcast failed: %w", err)
		}
	}

	// Register the Round 1 receiver after broadcast. Queued messages from
	// parties that already ran round1 will be replayed immediately.
	atomic.StoreInt32(&s.pending2, 1)
	s.params.broker.Connect(s.params.msgType(MsgTypeR1_44),
		tss.NewJsonExpect[signRound1msg44](s.params.msgType(MsgTypeR1_44), others, s.onR1))
	return nil
}

// computeCommitment is the hash commitment to a party's packed w: 32 bytes
// SHAKE256(Tr || keyId || wbuf).
func (s *Signing44) computeCommitment(keyId uint8, wbuf []byte) []byte {
	h := sha3.NewSHAKE256()
	h.Write(s.key.Tr[:])
	h.Write([]byte{keyId})
	h.Write(wbuf)
	out := make([]byte, 32)
	h.Read(out)
	return out
}

// committeeSlot returns the committee index of a given partyID.
func (s *Signing44) committeeSlot(from *tss.PartyID) int {
	for i, pid := range s.params.parties.IDs() {
		if pid.KeyInt().Cmp(from.KeyInt()) == 0 {
			return i
		}
	}
	return -1
}

// onR1 collects all other parties' Round 1 commitments, then kicks off Round 2.
func (s *Signing44) onR1(from []*tss.PartyID, msgs []*signRound1msg44) {
	if s.bail() {
		return
	}
	for i, pid := range from {
		slot := s.committeeSlot(pid)
		if slot < 0 {
			s.fail(fmt.Errorf("mldsatss: round1 sender %v not in committee", pid))
			return
		}
		if len(msgs[i].Commit) != 32 {
			s.fail(errors.New("mldsatss: round1 commitment size mismatch"))
			return
		}
		s.r1commits[slot] = msgs[i].Commit
	}
	if atomic.AddInt32(&s.pending2, -1) == 0 {
		s.round2()
	}
}

// round2 broadcasts this party's packed w's and computes μ.
func (s *Signing44) round2() {
	if s.bail() {
		return
	}
	// μ = SHAKE256(Tr || 0x00 || len(ctx) || ctx || msg)
	h := sha3.NewSHAKE256()
	h.Write(s.key.Tr[:])
	h.Write([]byte{0, byte(len(s.msgCtx))})
	h.Write(s.msgCtx)
	h.Write(s.msg)
	h.Read(s.mu[:])

	s.r2wbufs[s.myRank] = s.wbuf

	msg := &signRound2msg44{Wbuf: s.wbuf}
	others := s.otherPartyIDs()
	for _, pj := range others {
		if err := s.params.broker.Receive(tss.JsonWrap(
			s.params.msgType(MsgTypeR2_44), msg, s.params.partyID, pj,
		)); err != nil {
			s.fail(fmt.Errorf("mldsatss: round2 broadcast failed: %w", err))
			return
		}
	}

	atomic.StoreInt32(&s.pending3, 1)
	s.params.broker.Connect(s.params.msgType(MsgTypeR2_44),
		tss.NewJsonExpect[signRound2msg44](s.params.msgType(MsgTypeR2_44), others, s.onR2))
}

// onR2 collects other parties' raw packed w's, verifies each hash matches the
// corresponding Round 1 commitment, then kicks off Round 3.
func (s *Signing44) onR2(from []*tss.PartyID, msgs []*signRound2msg44) {
	if s.bail() {
		return
	}
	expectedBufLen := int(s.params.thParams.K) * mldsa.K44 * mldsa.PackPolyQSize
	for i, pid := range from {
		slot := s.committeeSlot(pid)
		if slot < 0 {
			s.fail(fmt.Errorf("mldsatss: round2 sender %v not in committee", pid))
			return
		}
		if len(msgs[i].Wbuf) != expectedBufLen {
			s.fail(fmt.Errorf("mldsatss: round2 wbuf size %d != expected %d", len(msgs[i].Wbuf), expectedBufLen))
			return
		}
		// Verify against the Round 1 commitment.
		have := s.computeCommitment(s.params.keyIds[slot], msgs[i].Wbuf)
		if !bytesEqual(have, s.r1commits[slot]) {
			s.fail(fmt.Errorf("mldsatss: round2 commitment mismatch for committee slot %d", slot))
			return
		}
		s.r2wbufs[slot] = msgs[i].Wbuf
	}
	if atomic.AddInt32(&s.pending3, -1) == 0 {
		s.round3()
	}
}

// round3 aggregates all w's, computes this party's K responses, and broadcasts them.
func (s *Signing44) round3() {
	if s.bail() {
		return
	}
	params := s.params.thParams

	// Aggregate w: wfinal[try][i] = Σ_{committee} w_try_from_party[i], mod q.
	wfinal := make([][mldsa.K44]mldsa.RingElement, params.K)
	for slot := 0; slot < int(params.T); slot++ {
		off := 0
		for tryIdx := 0; tryIdx < int(params.K); tryIdx++ {
			for i := 0; i < mldsa.K44; i++ {
				poly := mldsa.UnpackPolyQ(s.r2wbufs[slot][off : off+mldsa.PackPolyQSize])
				wfinal[tryIdx][i] = mldsa.PolyAdd(wfinal[tryIdx][i], poly)
				off += mldsa.PackPolyQSize
			}
		}
	}

	// Recover this party's partial secret (s1h, s2h) for the current act.
	s1h, s2h, err := s.key.recoverShare(s.act, params)
	if err != nil {
		s.fail(err)
		return
	}
	// Wipe the recovered secret-key material and the per-try secret nonces
	// (s.stws holds y) once this round is done with them. Best-effort.
	defer func() {
		zeroizeNttVecL44(&s1h)
		zeroizeNttVecK44(&s2h)
		for i := range s.stws {
			zeroizeFVec44(&s.stws[i])
		}
	}()

	// For each try, compute our contribution to z.
	resps := make([][mldsa.L44]mldsa.RingElement, params.K)
	for tryIdx := 0; tryIdx < int(params.K); tryIdx++ {
		w1 := highBitsVecK44(&wfinal[tryIdx])
		cTilde := computeCTilde44(s.mu[:], &w1)

		c := mldsa.SampleInBall44(cTilde[:])
		cHat := mldsa.NTT(c)

		// csW1 (L-part of zf) = c · s1h (InvNTT)
		var zPart [mldsa.L44]mldsa.RingElement
		for j := 0; j < mldsa.L44; j++ {
			zPart[j] = mldsa.InvNTT(mldsa.NttMul(cHat, s1h[j]))
		}
		// csW2 (K-part of zf) = c · s2h (InvNTT)
		var yPart [mldsa.K44]mldsa.RingElement
		for j := 0; j < mldsa.K44; j++ {
			yPart[j] = mldsa.InvNTT(mldsa.NttMul(cHat, s2h[j]))
		}

		var zf mldsa.FVec44
		zf.From(zPart[:], yPart[:])
		zf.Add(&zf, &s.stws[tryIdx])

		if zf.Excess(params.R, params.Nu) {
			// This try is rejected at the party — leave resps[tryIdx] as zeros.
			continue
		}
		// Round L-part back to integers in zPart; yPart is recycled but discarded.
		zf.Round(zPart[:], yPart[:])
		resps[tryIdx] = zPart
	}

	// Pack responses (K × L44 × EncodingSizeZ17 bytes).
	respBuf := make([]byte, int(params.K)*mldsa.L44*mldsa.EncodingSize18)
	off := 0
	for tryIdx := 0; tryIdx < int(params.K); tryIdx++ {
		for j := 0; j < mldsa.L44; j++ {
			copy(respBuf[off:], mldsa.PackZ17(resps[tryIdx][j]))
			off += mldsa.EncodingSize18
		}
	}
	s.r3resps[s.myRank] = respBuf

	msg := &signRound3msg44{Resp: respBuf}
	others := s.otherPartyIDs()
	for _, pj := range others {
		if err := s.params.broker.Receive(tss.JsonWrap(
			s.params.msgType(MsgTypeR3_44), msg, s.params.partyID, pj,
		)); err != nil {
			s.fail(fmt.Errorf("mldsatss: round3 broadcast failed: %w", err))
			return
		}
	}

	s.params.broker.Connect(s.params.msgType(MsgTypeR3_44),
		tss.NewJsonExpect[signRound3msg44](s.params.msgType(MsgTypeR3_44), others, s.onR3))
}

// onR3 collects responses and runs Combine locally.
func (s *Signing44) onR3(from []*tss.PartyID, msgs []*signRound3msg44) {
	if s.bail() {
		return
	}
	expectedRespLen := int(s.params.thParams.K) * mldsa.L44 * mldsa.EncodingSize18
	for i, pid := range from {
		slot := s.committeeSlot(pid)
		if slot < 0 {
			s.fail(fmt.Errorf("mldsatss: round3 sender %v not in committee", pid))
			return
		}
		if len(msgs[i].Resp) != expectedRespLen {
			s.fail(fmt.Errorf("mldsatss: round3 resp size %d != expected %d", len(msgs[i].Resp), expectedRespLen))
			return
		}
		s.r3resps[slot] = msgs[i].Resp
	}
	s.combine()
}

// combine aggregates responses, tries each of K attempts, and emits a FIPS 204
// signature on Done if any succeeds.
func (s *Signing44) combine() {
	if s.bail() {
		return
	}
	params := s.params.thParams

	// Aggregate zfinal[try][j] = Σ_{slot} z_try_from_party[j]
	zfinal := make([][mldsa.L44]mldsa.RingElement, params.K)
	for slot := 0; slot < int(params.T); slot++ {
		off := 0
		for tryIdx := 0; tryIdx < int(params.K); tryIdx++ {
			for j := 0; j < mldsa.L44; j++ {
				poly := mldsa.UnpackZ17(s.r3resps[slot][off : off+mldsa.EncodingSize18])
				zfinal[tryIdx][j] = mldsa.PolyAdd(zfinal[tryIdx][j], poly)
				off += mldsa.EncodingSize18
			}
		}
	}

	// Also aggregate wfinal again (cheap, and we haven't kept it around).
	wfinal := make([][mldsa.K44]mldsa.RingElement, params.K)
	for slot := 0; slot < int(params.T); slot++ {
		off := 0
		for tryIdx := 0; tryIdx < int(params.K); tryIdx++ {
			for i := 0; i < mldsa.K44; i++ {
				poly := mldsa.UnpackPolyQ(s.r2wbufs[slot][off : off+mldsa.PackPolyQSize])
				wfinal[tryIdx][i] = mldsa.PolyAdd(wfinal[tryIdx][i], poly)
				off += mldsa.PackPolyQSize
			}
		}
	}

	// Reconstruct t1 from the shared public key via the key's matrix A.
	// We need Power2Round-high values for the Az − 2^d·c·t1 check. The
	// simplest source: re-derive from pk bytes; but we only have Key44
	// here. We instead use the aggregated secrets' implicit t1: since
	// each party already baked t1 into the public key, and we computed
	// t1 during trusted-dealer keygen, we keep a cached value on the key.
	// For v1 we recompute t1 from the full share store (trusted-dealer
	// mode) — every key holds every share for t == n, but for t < n only a
	// subset. To avoid that, we require the caller to hand in a PublicKey
	// (see Signer). However, Combine is internal and we simply aggregate
	// t1 via s1h summed across ALL shares that any party holds — but that
	// is not deterministic across parties in non-trivial (t, n).
	//
	// Practical fix: Combine needs t1 via the PublicKey. Attach it to the
	// Key44 on keygen.
	// See Key44.T1 field (populated during TrustedDealerKeygen44).
	t1 := s.key.T1

	// For each try, attempt to produce a FIPS 204 signature.
	sigBuf := make([]byte, mldsa.Lambda128/4+mldsa.L44*mldsa.EncodingSize18+mldsa.Omega80+mldsa.K44)
	for tryIdx := 0; tryIdx < int(params.K); tryIdx++ {
		// ‖z‖_∞ < γ1 − β?
		if !zWithinBound(&zfinal[tryIdx], mldsa.Gamma1Pow17-mldsa.Beta44) {
			continue
		}

		// c~ = H(μ ‖ w₁(wfinal))
		w1 := highBitsVecK44(&wfinal[tryIdx])
		cTilde := computeCTilde44(s.mu[:], &w1)

		c := mldsa.SampleInBall44(cTilde[:])
		cHat := mldsa.NTT(c)

		// Compute Az (NTT).
		var Az [mldsa.K44]mldsa.NttElement
		var zHat [mldsa.L44]mldsa.NttElement
		for j := 0; j < mldsa.L44; j++ {
			zHat[j] = mldsa.NTT(zfinal[tryIdx][j])
		}
		A := s.key.Matrix()
		for i := 0; i < mldsa.K44; i++ {
			var acc mldsa.NttElement
			for j := 0; j < mldsa.L44; j++ {
				acc = mldsa.PolyAdd(acc, mldsa.NttMul(A[i*mldsa.L44+j], zHat[j]))
			}
			Az[i] = acc
		}

		// Az − 2^d·c·t1 (NTT).
		var Az2dct1 [mldsa.K44]mldsa.RingElement
		for i := 0; i < mldsa.K44; i++ {
			// 2^d · t1 in NTT form
			var t1Scaled mldsa.RingElement
			for j := 0; j < mldsa.N; j++ {
				t1Scaled[j] = t1[i][j] << mldsa.D
			}
			t1Hat := mldsa.NTT(t1Scaled)
			ct1 := mldsa.NttMul(cHat, t1Hat)
			diff := mldsa.PolySub(Az[i], ct1)
			Az2dct1[i] = mldsa.InvNTT(diff)
		}

		// f = (Az − 2^d·c·t1) − wfinal  — should have |·|_∞ < γ₂ if valid.
		var f [mldsa.K44]mldsa.RingElement
		for i := 0; i < mldsa.K44; i++ {
			f[i] = mldsa.PolySub(Az2dct1[i], wfinal[tryIdx][i])
		}
		if mldsa.VectorInfinityNorm(f[:]) >= mldsa.Gamma2QMinus1Div88 {
			continue
		}

		// Compute hint = 1 iff adding f to the low bits of wfinal changes the
		// high-bits bucket. This matches the reference's makeHint(z0, r1) —
		// a low-bits/high-bits variant (rounding.go:56-67 in thmldsa44), not
		// FIPS 204's full-value MakeHint(z, r).
		var hints [mldsa.K44]mldsa.RingElement
		for i := 0; i < mldsa.K44; i++ {
			for j := 0; j < mldsa.N; j++ {
				_, r0 := mldsa.Decompose44(wfinal[tryIdx][i][j])
				var w0Mod uint32
				if r0 < 0 {
					w0Mod = mldsa.Q - uint32(-r0)
				} else {
					w0Mod = uint32(r0)
				}
				z0 := w0Mod + uint32(f[i][j])
				if z0 >= mldsa.Q {
					z0 -= mldsa.Q
				}
				hints[i][j] = mldsa.FieldElement(makeHintLowBits44(z0, uint32(w1[i][j])))
			}
		}
		if mldsa.CountOnes(hints[:]) > mldsa.Omega80 {
			continue
		}

		// Assemble (c~, z, hint).
		copy(sigBuf[:mldsa.Lambda128/4], cTilde[:])
		off := mldsa.Lambda128 / 4
		for j := 0; j < mldsa.L44; j++ {
			copy(sigBuf[off:], mldsa.PackZ17(zfinal[tryIdx][j]))
			off += mldsa.EncodingSize18
		}
		copy(sigBuf[off:], mldsa.PackHint44(hints[:]))

		// Emit signature and stop.
		s.Done <- &SignatureData{Signature: append([]byte(nil), sigBuf...)}
		return
	}

	s.fail(ErrAllTriesRejected)
}

// --- helpers ---------------------------------------------------------------

// highBitsVecK44 returns w₁ (HighBits) of a VecK as a RingElement-valued
// array (each coefficient in [0, 44) for ML-DSA-44's γ₂=(q−1)/88).
func highBitsVecK44(w *[mldsa.K44]mldsa.RingElement) [mldsa.K44]mldsa.RingElement {
	var out [mldsa.K44]mldsa.RingElement
	for i := 0; i < mldsa.K44; i++ {
		for j := 0; j < mldsa.N; j++ {
			out[i][j] = mldsa.FieldElement(mldsa.HighBits44(w[i][j]))
		}
	}
	return out
}

// computeCTilde44 computes c~ = SHAKE256(μ ‖ PackW1(w₁)) → λ/4 bytes.
func computeCTilde44(mu []byte, w1 *[mldsa.K44]mldsa.RingElement) [mldsa.Lambda128 / 4]byte {
	h := sha3.NewSHAKE256()
	h.Write(mu)
	for i := 0; i < mldsa.K44; i++ {
		h.Write(mldsa.PackW1_44(w1[i]))
	}
	var out [mldsa.Lambda128 / 4]byte
	h.Read(out[:])
	return out
}

// zWithinBound reports whether every coefficient of z has infinity norm < bound.
func zWithinBound(z *[mldsa.L44]mldsa.RingElement, bound uint32) bool {
	for i := 0; i < mldsa.L44; i++ {
		if mldsa.PolyInfinityNorm(z[i]) >= bound {
			return false
		}
	}
	return true
}

// makeHintLowBits44 returns 1 iff adding a perturbation to the low bits of a
// decomposition crosses a high-bits bucket boundary. This matches the
// reference implementation's makeHint(z0, r1) — a two-valued variant where
// z0 is the perturbed low bits (in [0, q), signed-shifted) and r1 is the
// original high-bits index (in [0, 44) for ML-DSA-44). It differs from
// FIPS 204's full-value MakeHint(z, r). The produced hint is valid input
// for FIPS 204 UseHint.
func makeHintLowBits44(z0, r1 uint32) uint32 {
	const g = mldsa.Gamma2QMinus1Div88
	if z0 <= g || z0 > mldsa.Q-g || (z0 == mldsa.Q-g && r1 == 0) {
		return 0
	}
	return 1
}

// bail returns true if the context is cancelled; in that case it also sends to Err.
func (s *Signing44) bail() bool {
	if err := s.ctx.Err(); err != nil {
		select {
		case s.Err <- err:
		default:
		}
		return true
	}
	return false
}

// fail sends an error to Err (non-blocking).
func (s *Signing44) fail(err error) {
	select {
	case s.Err <- err:
	default:
	}
}

// bytesEqual is a simple constant-time comparison wrapper (public-data here,
// so constant-time is not a security requirement).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
