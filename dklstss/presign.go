package dklstss

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/ole"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ErrPresignAlreadyConsumed is returned by SignWithPresign when its input
// has already been used to sign once. Re-using presigning state is
// equivalent to re-using an ECDSA nonce: it leads to private-key
// extraction by any observer who sees both signatures.
var ErrPresignAlreadyConsumed = errors.New("dklstss: presign output already consumed — reuse equals nonce reuse equals key extraction")

// PresignOutput is the result of the offline phase of signing. It binds
// to a specific (public key, signing subset, group nonce R) and may be
// consumed by SignWithPresign exactly ONCE.
//
// Single-use enforcement is implemented by an atomic compare-and-swap on
// the `consumed` flag. Once consumed, the struct is logically dead — any
// subsequent SignWithPresign call returns ErrPresignAlreadyConsumed.
//
// For long-term storage (e.g., precomputing presigns offline and signing
// later), the caller MUST also maintain a durable record of consumed
// presigns (a set of R.X mod q values) so reuse across crash-restart
// boundaries is also rejected. This package does not persist that record;
// callers should derive a hash from R.X and check against their own
// persistent store before invoking SignWithPresign.
type PresignOutput struct {
	// Identifying material — same across all parties.
	Pub       *crypto.ECPoint
	R         *crypto.ECPoint
	r         *big.Int // R.x mod q
	signerIdx []int
	keys      []*Key

	// Per-party offline state. When aggregated == true, parties holds
	// the joint shares from ALL T+1 signers and the slice is consumable
	// by SignWithPresign. When aggregated == false, parties holds only
	// the local party's slice (one entry) — the broker-driven
	// PresignParty produces this form and an online-sign protocol must
	// compose shares from every signer to form a signature.
	parties []*partyPresign

	// aggregated distinguishes a fully-composed PresignOutput (sync
	// Presign) from a per-party share (broker-driven PresignParty).
	// SignWithPresign refuses to consume an unaggregated output —
	// silently aggregating one party's shares would produce a
	// non-verifying signature.
	aggregated bool

	consumed atomic.Bool
}

type partyPresign struct {
	rho       *big.Int
	sigma     *big.Int // shares of x · ρ (Lagrange-scaled)
	kRhoShare *big.Int // shares of k · ρ
}

// Presign runs the offline (pre-signing) phase. It does NOT consume the
// message digest — that is supplied later to SignWithPresign.
//
// On success, returns a PresignOutput that may be consumed once. Multiple
// successful Presign calls (with fresh randomness) produce independent
// outputs that can each be consumed once.
func Presign(keys []*Key, signerIdx []int, rng io.Reader) (*PresignOutput, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if len(keys) == 0 {
		return nil, errors.New("dklstss: Presign requires at least one key")
	}
	n := keys[0].N
	t := keys[0].T
	pub := keys[0].ECDSAPub
	if len(signerIdx) != t+1 {
		return nil, fmt.Errorf("dklstss: Presign requires T+1=%d signers, got %d", t+1, len(signerIdx))
	}
	seen := make(map[int]struct{}, len(signerIdx))
	for _, idx := range signerIdx {
		if idx < 0 || idx >= n {
			return nil, fmt.Errorf("dklstss: Presign signerIdx %d out of range", idx)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("dklstss: Presign duplicate signerIdx %d", idx)
		}
		seen[idx] = struct{}{}
	}
	ec := tss.S256()
	q := ec.Params().N

	sgn := len(signerIdx)
	signers := make([]*Key, sgn)
	for i, idx := range signerIdx {
		signers[i] = keys[idx]
		if signers[i].N != n || signers[i].T != t || !signers[i].ECDSAPub.Equals(pub) {
			return nil, fmt.Errorf("dklstss: Presign key %d inconsistent", idx)
		}
	}

	ids := make([]*big.Int, sgn)
	for i, k := range signers {
		ids[i] = k.PartyIDs[k.Idx].KeyInt()
	}
	lambdas := make([]*big.Int, sgn)
	for i := range signers {
		lam, err := lagrangeCoefficient(q, ids, i)
		if err != nil {
			return nil, fmt.Errorf("dklstss: Presign lagrange: %w", err)
		}
		lambdas[i] = lam
	}
	sx := make([]*big.Int, sgn)
	for i := range signers {
		sx[i] = new(big.Int).Mul(lambdas[i], signers[i].Xi)
		sx[i].Mod(sx[i], q)
	}

	var ssidNonce [16]byte
	if _, err := io.ReadFull(rng, ssidNonce[:]); err != nil {
		return nil, fmt.Errorf("dklstss: Presign ssid: %w", err)
	}
	ssid := append([]byte("DKLS23-presign-v1-"), ssidNonce[:]...)

	k := make([]*big.Int, sgn)
	rho := make([]*big.Int, sgn)
	Ki := make([]*crypto.ECPoint, sgn)
	for i := range signers {
		k[i] = common.GetRandomPositiveInt(rng, q)
		rho[i] = common.GetRandomPositiveInt(rng, q)
		// Nonce share k_i is the most critical secret scalar — route
		// k_i · G through the constant-time scalar mult.
		Ki[i] = ctmul.ScalarBaseMultWithRand(ec, k[i], rng)
	}
	R := Ki[0]
	for i := 1; i < sgn; i++ {
		var err error
		R, err = R.Add(Ki[i])
		if err != nil {
			return nil, fmt.Errorf("dklstss: Presign R aggregation: %w", err)
		}
	}
	r := new(big.Int).Mod(R.X(), q)
	if r.Sign() == 0 {
		return nil, errors.New("dklstss: Presign R.X mod q is 0; retry")
	}

	kRhoShare := make([]*big.Int, sgn)
	xRhoShare := make([]*big.Int, sgn)
	for i := range signers {
		kRhoShare[i] = new(big.Int).Mul(k[i], rho[i])
		kRhoShare[i].Mod(kRhoShare[i], q)
		xRhoShare[i] = new(big.Int).Mul(sx[i], rho[i])
		xRhoShare[i].Mod(xRhoShare[i], q)
	}

	for ai := 0; ai < sgn; ai++ {
		for bj := 0; bj < sgn; bj++ {
			if ai == bj {
				continue
			}
			aliceKey := signers[ai]
			bobKey := signers[bj]
			alicePair := aliceKey.OT[bobKey.Idx]
			bobPair := bobKey.OT[aliceKey.Idx]
			if alicePair == nil || bobPair == nil {
				return nil, fmt.Errorf("dklstss: Presign missing OT state (%d,%d)", aliceKey.Idx, bobKey.Idx)
			}

			sidK := makeSid(ssid, "presign-kxrho", aliceKey.Idx, bobKey.Idx)
			aMsgK, aStK, err := ole.AliceStep1(sidK, alicePair.AsAlice, k[ai])
			if err != nil {
				return nil, fmt.Errorf("dklstss: Presign ΠMul-k1: %w", err)
			}
			bMsgK, uBK, err := ole.BobStep1(sidK, bobPair.AsBob, rho[bj], aMsgK)
			if err != nil {
				return nil, fmt.Errorf("dklstss: Presign ΠMul-kB: %w", err)
			}
			uAK, err := ole.AliceStep2(aStK, bMsgK)
			if err != nil {
				return nil, fmt.Errorf("dklstss: Presign ΠMul-kA: %w", err)
			}
			kRhoShare[ai] = addMod(q, kRhoShare[ai], uAK)
			kRhoShare[bj] = addMod(q, kRhoShare[bj], uBK)

			sidX := makeSid(ssid, "presign-xxrho", aliceKey.Idx, bobKey.Idx)
			aMsgX, aStX, err := ole.AliceStep1(sidX, alicePair.AsAlice, sx[ai])
			if err != nil {
				return nil, fmt.Errorf("dklstss: Presign ΠMul-x1: %w", err)
			}
			bMsgX, uBX, err := ole.BobStep1(sidX, bobPair.AsBob, rho[bj], aMsgX)
			if err != nil {
				return nil, fmt.Errorf("dklstss: Presign ΠMul-xB: %w", err)
			}
			uAX, err := ole.AliceStep2(aStX, bMsgX)
			if err != nil {
				return nil, fmt.Errorf("dklstss: Presign ΠMul-xA: %w", err)
			}
			xRhoShare[ai] = addMod(q, xRhoShare[ai], uAX)
			xRhoShare[bj] = addMod(q, xRhoShare[bj], uBX)
		}
	}

	parties := make([]*partyPresign, sgn)
	for i := range signers {
		parties[i] = &partyPresign{
			rho:       rho[i],
			sigma:     xRhoShare[i],
			kRhoShare: kRhoShare[i],
		}
	}

	return &PresignOutput{
		Pub:        pub,
		R:          R,
		r:          r,
		signerIdx:  append([]int(nil), signerIdx...),
		keys:       keys,
		parties:    parties,
		aggregated: true,
	}, nil
}

// UsedPresignStore is the caller-supplied interface that persists the
// set of presign-output R-hashes already consumed by SignWithPresign.
// A correct implementation MUST survive process restart and node
// failure: re-using a presign across crash-restart is equivalent to
// ECDSA nonce reuse and reveals the private key.
//
// CheckAndRecord MUST be atomic: it returns (true, nil) iff the hash was
// not present BEFORE this call AND was successfully recorded. Any error
// (e.g. storage failure) MUST be returned. A correct implementation
// should fsync-or-equivalent before returning success.
type UsedPresignStore interface {
	CheckAndRecord(rHash []byte) (recorded bool, err error)
}

// InMemoryPresignStore is a non-durable UsedPresignStore for tests. Do
// NOT use in production — it does not survive process restart. The set
// of consumed R-hashes lives in a sync.Map that grows unboundedly with
// the number of presigns; for production-scale durable storage, back
// the interface by a Redis/etcd/persisted-file store.
type InMemoryPresignStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// NewInMemoryPresignStore returns an empty in-memory store.
func NewInMemoryPresignStore() *InMemoryPresignStore {
	return &InMemoryPresignStore{seen: make(map[string]struct{})}
}

// CheckAndRecord implements UsedPresignStore.
func (s *InMemoryPresignStore) CheckAndRecord(rHash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := string(rHash)
	if _, present := s.seen[k]; present {
		return false, nil
	}
	s.seen[k] = struct{}{}
	return true, nil
}

// SignWithPresign consumes a PresignOutput exactly once and finalizes the
// ECDSA signature against `hash`. Subsequent calls return
// ErrPresignAlreadyConsumed.
//
// The presign output may also be consumed atomically with an optional
// HD tweak: pass a non-nil tweak to derive the signature under a BIP32
// child key. The verifier should then use the derived child public key.
//
// For durable (cross-restart) single-use enforcement, use
// SignWithPresignDurable, which consults a caller-supplied
// UsedPresignStore before consuming.
func SignWithPresign(presign *PresignOutput, hash []byte, tweak *big.Int) (*Signature, error) {
	if presign == nil {
		return nil, errors.New("dklstss: SignWithPresign nil presign")
	}
	if len(hash) == 0 {
		return nil, errors.New("dklstss: SignWithPresign hash must be non-empty")
	}
	if !presign.aggregated {
		// Per-party PresignOutput from broker-driven PresignParty;
		// composing one signer's shares alone produces a non-verifying
		// signature. Refuse explicitly rather than silently emit
		// garbage. The CAS is NOT flipped on this path so the per-party
		// share can still be fed into an online-sign protocol.
		return nil, errors.New("dklstss: SignWithPresign requires an aggregated PresignOutput; the per-party output from PresignParty must be composed by an online sign protocol")
	}
	// Atomic CAS: only one caller can flip false → true; others get the
	// already-consumed error.
	if !presign.consumed.CompareAndSwap(false, true) {
		return nil, ErrPresignAlreadyConsumed
	}

	q := tss.S256().Params().N
	sgn := len(presign.parties)

	// φ = Σ kRhoShare = k · ρ.
	phi := new(big.Int)
	for _, p := range presign.parties {
		phi.Add(phi, p.kRhoShare)
		phi.Mod(phi, q)
	}
	if phi.Sign() == 0 {
		return nil, errors.New("dklstss: SignWithPresign φ is 0; presign was malformed")
	}

	// Tweak: add to first signer's σ contribution. hashToScalar applies
	// SEC 1 §4.1.3 leftmost-bits truncation; required for digests longer
	// than the curve order to round-trip through crypto/ecdsa.Verify.
	hashI := hashToScalar(q, hash)

	// HD tweak handling: with tweak τ, the effective signing key is
	// x_new = x + τ, so σ_new = x_new · ρ = σ + τ · ρ. Since ρ = Σ ρ_j,
	// each party j adds τ · ρ_j to its σ_j share. (Party-0-only absorption
	// would miss the cross-term contributions τ · ρ_j for j ≠ 0.)
	var tweakMod *big.Int
	if tweak != nil {
		tweakMod = new(big.Int).Mod(tweak, q)
	}

	sigmaSum := new(big.Int)
	for i := 0; i < sgn; i++ {
		sigma := presign.parties[i].sigma
		if tweakMod != nil {
			extra := new(big.Int).Mul(tweakMod, presign.parties[i].rho)
			extra.Mod(extra, q)
			sigma = new(big.Int).Add(sigma, extra)
			sigma.Mod(sigma, q)
		}
		t1 := new(big.Int).Mul(presign.parties[i].rho, hashI)
		t1.Mod(t1, q)
		t2 := new(big.Int).Mul(presign.r, sigma)
		t2.Mod(t2, q)
		shati := new(big.Int).Add(t1, t2)
		shati.Mod(shati, q)
		sigmaSum.Add(sigmaSum, shati)
		sigmaSum.Mod(sigmaSum, q)
	}

	phiInv := common.ModInt(q).ModInverse(phi)
	if phiInv == nil {
		return nil, errors.New("dklstss: SignWithPresign φ has no inverse")
	}
	s := new(big.Int).Mul(sigmaSum, phiInv)
	s.Mod(s, q)
	if s.Sign() == 0 {
		return nil, errors.New("dklstss: SignWithPresign produced s=0")
	}

	halfQ := new(big.Int).Rsh(q, 1)
	v := byte(presign.R.Y().Bit(0))
	if s.Cmp(halfQ) > 0 {
		s.Sub(q, s)
		v ^= 1
	}
	return &Signature{R: new(big.Int).Set(presign.r), S: s, V: v}, nil
}

// SignWithPresignDurable is SignWithPresign with cross-restart single-use
// enforcement via a caller-supplied UsedPresignStore. The store is
// consulted BEFORE the in-memory CAS: if the presign's R-hash is already
// recorded, SignWithPresignDurable returns ErrPresignAlreadyConsumed
// without consuming the in-memory flag, ensuring the same presign is
// rejected by any node holding the durable record.
//
// Callers should use this in production. SignWithPresign is reserved
// for tests where durable storage is not warranted.
func SignWithPresignDurable(presign *PresignOutput, hash []byte, tweak *big.Int, store UsedPresignStore) (*Signature, error) {
	if presign == nil {
		return nil, errors.New("dklstss: SignWithPresignDurable nil presign")
	}
	if !presign.aggregated {
		// Reject before touching the store so a misuse doesn't burn an
		// R-hash record on a presign that can't actually sign.
		return nil, errors.New("dklstss: SignWithPresignDurable requires an aggregated PresignOutput; the per-party output from PresignParty must be composed by an online sign protocol")
	}
	if store == nil {
		return nil, errors.New("dklstss: SignWithPresignDurable nil store; use SignWithPresign for in-memory-only")
	}
	rHash := presign.RHash()
	recorded, err := store.CheckAndRecord(rHash)
	if err != nil {
		return nil, fmt.Errorf("dklstss: SignWithPresignDurable store error: %w", err)
	}
	if !recorded {
		// Already in the store — refuse to consume the in-memory presign.
		return nil, ErrPresignAlreadyConsumed
	}
	return SignWithPresign(presign, hash, tweak)
}

// RHash returns a 32-byte hash uniquely identifying this presign's R, for
// callers maintaining a durable consumed-presigns set. Two presigns with
// the same R should never both be consumed; if `RHash` matches a record
// in the caller's persistent store, refuse to invoke SignWithPresign.
func (p *PresignOutput) RHash() []byte {
	h := common.SHA512_256i_TAGGED([]byte("DKLS23-presign-rhash-v1"), p.R.X(), p.R.Y())
	return h.Bytes()
}

// Consumed reports whether the presign has been consumed.
func (p *PresignOutput) Consumed() bool {
	return p.consumed.Load()
}
