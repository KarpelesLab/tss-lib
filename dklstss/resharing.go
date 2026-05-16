package dklstss

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Reshare transfers the joint secret from an old committee to a new
// committee (possibly with different N, T, or party membership) while
// preserving the joint public key.
//
// Inputs:
//   - oldKeys: the slice of all N_old Keys (only oldSubsetIdx parties
//     actually participate; the others can be nil placeholders).
//   - oldSubsetIdx: indices into oldKeys of the participating parties.
//     Must contain at least T_old + 1 distinct indices.
//   - newPartyIDs: sorted party IDs for the new committee.
//   - newThreshold: threshold for the new committee (T_new). Signing
//     after resharing requires T_new + 1 parties.
//
// Output: one *Key per new committee member, in the order of
// newPartyIDs. Per-party OT extension state is freshly established
// between every pair of new committee members.
//
// Security: each old party sends Feldman-VSS shares of its
// Lagrange-scaled local secret to the new committee. The new committee
// reconstructs by summing received shares; the resulting joint
// polynomial has constant term equal to x (the original secret),
// preserving the public key.
//
// This is the synchronous in-process variant. A broker-driven
// equivalent (task #28) will route messages per party.
func Reshare(oldKeys []*Key, oldSubsetIdx []int, newPartyIDs tss.SortedPartyIDs, newThreshold int, rng io.Reader) ([]*Key, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if len(oldKeys) == 0 {
		return nil, fmt.Errorf("dklstss: Reshare requires at least one old key")
	}
	tOld := oldKeys[0].T
	nNew := len(newPartyIDs)
	tNew := newThreshold

	if len(oldSubsetIdx) < tOld+1 {
		return nil, fmt.Errorf("dklstss: Reshare needs at least %d old participants, got %d", tOld+1, len(oldSubsetIdx))
	}
	if nNew == 0 {
		return nil, fmt.Errorf("dklstss: Reshare needs non-empty new committee")
	}
	if tNew < 1 || tNew >= nNew {
		return nil, fmt.Errorf("dklstss: Reshare requires 1 ≤ T_new < N_new, got T=%d N=%d", tNew, nNew)
	}

	// Resolve old participants and validate consistency.
	pub := oldKeys[oldSubsetIdx[0]].ECDSAPub
	chainCode := oldKeys[oldSubsetIdx[0]].ChainCode
	ec := oldKeys[oldSubsetIdx[0]].Curve
	q := ec.Params().N

	seen := make(map[int]struct{}, len(oldSubsetIdx))
	oldParticipants := make([]*Key, len(oldSubsetIdx))
	for i, idx := range oldSubsetIdx {
		if idx < 0 || idx >= len(oldKeys) {
			return nil, fmt.Errorf("dklstss: Reshare oldSubsetIdx %d out of range", idx)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("dklstss: Reshare duplicate oldSubsetIdx %d", idx)
		}
		seen[idx] = struct{}{}
		if oldKeys[idx] == nil {
			return nil, fmt.Errorf("dklstss: Reshare oldKeys[%d] is nil", idx)
		}
		if !oldKeys[idx].ECDSAPub.Equals(pub) {
			return nil, fmt.Errorf("dklstss: Reshare oldKeys[%d] has inconsistent public key", idx)
		}
		oldParticipants[i] = oldKeys[idx]
	}

	// Validate new party IDs are distinct and non-zero mod q.
	newIDs := make([]*big.Int, nNew)
	for i, pid := range newPartyIDs {
		newIDs[i] = pid.KeyInt()
	}
	if _, err := vss.CheckIndexes(ec, newIDs); err != nil {
		return nil, fmt.Errorf("dklstss: Reshare invalid new party IDs: %w", err)
	}

	// Compute Lagrange coefficients of the old subset.
	oldIDs := make([]*big.Int, len(oldParticipants))
	for i, k := range oldParticipants {
		oldIDs[i] = k.PartyIDs[k.Idx].KeyInt()
	}
	oldLambdas := make([]*big.Int, len(oldParticipants))
	for i := range oldParticipants {
		lam, err := lagrangeCoefficient(q, oldIDs, i)
		if err != nil {
			return nil, fmt.Errorf("dklstss: Reshare lagrange: %w", err)
		}
		oldLambdas[i] = lam
	}

	// Phase 1: each old participant scales its share by its old-Lagrange
	// coefficient and Feldman-shares this scaled share to the new committee.
	commitments := make([]vss.Vs, len(oldParticipants))
	shares := make([]vss.Shares, len(oldParticipants))
	for i, k := range oldParticipants {
		scaled := new(big.Int).Mul(oldLambdas[i], k.Xi)
		scaled.Mod(scaled, q)
		if scaled.Sign() == 0 {
			// λ·x mod q == 0 is statistically impossible for honest
			// random shares (probability ~ 1/q ≈ 2^-256). Treat as a
			// fatal protocol abort rather than silently substituting a
			// non-zero scalar — substitution would change the joint
			// secret by a known amount and the downstream pubkey-equality
			// check would reject anyway, but with a misleading error.
			return nil, fmt.Errorf("dklstss: Reshare old participant %d has λ·x_i ≡ 0 mod q (key material likely corrupted)", oldSubsetIdx[i])
		}
		Vs, S, err := vss.Create(ec, tNew, scaled, newIDs, rng)
		if err != nil {
			return nil, fmt.Errorf("dklstss: Reshare VSS create old party %d: %w", i, err)
		}
		commitments[i] = Vs
		shares[i] = S
	}

	// Phase 2: each new party verifies its incoming shares and sums them.
	// Joint polynomial F(x) = Σ_i f_i(x), so F(0) = Σ_i λ_i·x_i = x. ✓
	newXj := make([]*big.Int, nNew)
	for j := 0; j < nNew; j++ {
		sum := new(big.Int)
		for i, S := range shares {
			sh := S[j]
			if !sh.Verify(ec, tNew, commitments[i]) {
				return nil, fmt.Errorf("dklstss: Reshare share from old party %d to new party %d failed VSS verify", oldSubsetIdx[i], j)
			}
			sum.Add(sum, sh.Share)
			sum.Mod(sum, q)
		}
		newXj[j] = sum
	}

	// Phase 3: compute BigXj for the new committee. BigXj[j] = newXj[j]·G.
	newBigXj := make([]*crypto.ECPoint, nNew)
	for j := 0; j < nNew; j++ {
		newBigXj[j] = crypto.ScalarBaseMult(ec, newXj[j])
		// Sanity: also check against summed Feldman commitments
		// evaluated at id_j.
		Xj, err := evaluateCommitmentSum(ec, commitments, newIDs[j])
		if err != nil {
			return nil, fmt.Errorf("dklstss: Reshare BigXj[%d] check: %w", j, err)
		}
		if !Xj.Equals(newBigXj[j]) {
			return nil, fmt.Errorf("dklstss: Reshare BigXj[%d] inconsistent with VSS commitments", j)
		}
	}

	// Phase 4: verify the public key is preserved.
	// X = Σ_i v_i where v_i = commitments[i][0] = scaled_share_i · G.
	// Σ scaled_share_i = Σ λ_i·x_i = x mod q. So Σ v_i = x · G = pub.
	reconstructed := commitments[0][0]
	for i := 1; i < len(commitments); i++ {
		var err error
		reconstructed, err = reconstructed.Add(commitments[i][0])
		if err != nil {
			return nil, fmt.Errorf("dklstss: Reshare pubkey check add: %w", err)
		}
	}
	if !reconstructed.Equals(pub) {
		return nil, fmt.Errorf("dklstss: Reshare reconstructed public key does not match original — protocol error")
	}

	// Phase 5: fresh pairwise OT setup for the new committee.
	var nonce [16]byte
	if _, err := io.ReadFull(rng, nonce[:]); err != nil {
		return nil, fmt.Errorf("dklstss: Reshare OT nonce: %w", err)
	}
	sidPrefix := append([]byte("DKLS23-reshare-otsetup-v1-"), pub.X().Bytes()...)
	sidPrefix = append(sidPrefix, '|')
	sidPrefix = append(sidPrefix, nonce[:]...)
	ot, err := setupPairs(nNew, sidPrefix, rng)
	if err != nil {
		return nil, fmt.Errorf("dklstss: Reshare OT setup: %w", err)
	}

	// Phase 6: assemble new keys.
	out := make([]*Key, nNew)
	for i := 0; i < nNew; i++ {
		out[i] = &Key{
			Curve:     ec,
			N:         nNew,
			T:         tNew,
			Idx:       i,
			PartyIDs:  newPartyIDs,
			Xi:        newXj[i],
			BigXj:     newBigXj,
			ECDSAPub:  pub,
			OT:        ot[i],
			ChainCode: append([]byte(nil), chainCode...),
		}
		if err := out[i].ValidateBasic(); err != nil {
			return nil, fmt.Errorf("dklstss: Reshare produced invalid key for new party %d: %w", i, err)
		}
	}
	return out, nil
}

// Silence unused.
var _ = common.RejectionSample
