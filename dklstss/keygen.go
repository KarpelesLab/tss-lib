package dklstss

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Keygen runs an n-party t-of-n DKG in-process and returns one Key per
// party in the order partyIDs are passed.
//
// Threshold semantics: signing requires any T+1 parties. T is the
// polynomial degree of the Feldman VSS; T must satisfy 1 ≤ T < N.
//
// This is the synchronous test/integration API. A broker-driven async API
// (task #7) wraps this with message routing.
func Keygen(n, t int, partyIDs tss.SortedPartyIDs, rng io.Reader) ([]*Key, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if n <= 0 {
		return nil, fmt.Errorf("dklstss: Keygen n must be > 0, got %d", n)
	}
	if t < 1 || t >= n {
		return nil, fmt.Errorf("dklstss: Keygen requires 1 ≤ T < N, got T=%d N=%d", t, n)
	}
	if len(partyIDs) != n {
		return nil, fmt.Errorf("dklstss: Keygen partyIDs length %d, expected %d", len(partyIDs), n)
	}
	ec := tss.S256()
	q := ec.Params().N

	ids := make([]*big.Int, n)
	for i, pid := range partyIDs {
		ids[i] = pid.KeyInt()
	}
	if _, err := vss.CheckIndexes(ec, ids); err != nil {
		return nil, fmt.Errorf("dklstss: Keygen invalid party indexes: %w", err)
	}

	// Phase 1: each party samples u_i, Feldman-VSS shares it.
	commitments := make([]vss.Vs, n)
	shares := make([]vss.Shares, n)
	for i := 0; i < n; i++ {
		u := common.GetRandomPositiveInt(rng, q)
		Vs, S, err := vss.Create(ec, t, u, ids, rng)
		if err != nil {
			return nil, fmt.Errorf("dklstss: Keygen VSS create for party %d: %w", i, err)
		}
		commitments[i] = Vs
		shares[i] = S
	}

	// Phase 2: each party j receives a share from each peer i. Verify and
	// sum to compute the local Shamir share x_j.
	xj := make([]*big.Int, n)
	for j := 0; j < n; j++ {
		sum := new(big.Int)
		for i := 0; i < n; i++ {
			// shares[i] is indexed by recipient party position (same order as ids).
			sh := shares[i][j]
			if !sh.Verify(ec, t, commitments[i]) {
				return nil, fmt.Errorf("dklstss: Keygen share from party %d to party %d failed VSS verification", i, j)
			}
			sum.Add(sum, sh.Share)
			sum.Mod(sum, q)
		}
		xj[j] = sum
	}

	// Phase 3: compute public commitments.
	// Joint public key X = Σ commitments[i][0] (each is u_i · G).
	pub := commitments[0][0]
	for i := 1; i < n; i++ {
		var err error
		pub, err = pub.Add(commitments[i][0])
		if err != nil {
			return nil, fmt.Errorf("dklstss: Keygen pubkey aggregation: %w", err)
		}
	}
	// Each party's BigXj[j] = x_j · G (independently computable by summing
	// Feldman commitments evaluated at id_j).
	BigXj := make([]*crypto.ECPoint, n)
	for j := 0; j < n; j++ {
		Xj, err := evaluateCommitmentSum(ec, commitments, ids[j])
		if err != nil {
			return nil, fmt.Errorf("dklstss: Keygen BigXj[%d]: %w", j, err)
		}
		BigXj[j] = Xj
		// Sanity: x_j · G should equal BigXj[j].
		expected := crypto.ScalarBaseMult(ec, xj[j])
		if !expected.Equals(Xj) {
			return nil, fmt.Errorf("dklstss: Keygen BigXj[%d] does not match x_j · G", j)
		}
	}

	// Phase 4: pairwise OT setup.
	sidPrefix := append([]byte("DKLS23-dkg-otsetup-v1-"), pub.X().Bytes()...)
	ot, err := setupPairs(n, sidPrefix, rng)
	if err != nil {
		return nil, fmt.Errorf("dklstss: Keygen OT setup: %w", err)
	}

	// Compute BIP32 chain code: deterministic hash of the joint public key
	// with domain separation. All parties derive the same value.
	chainCode := deriveChainCode(pub)

	// Phase 5: assemble per-party Key structs.
	out := make([]*Key, n)
	for i := 0; i < n; i++ {
		out[i] = &Key{
			Curve:     ec,
			N:         n,
			T:         t,
			Idx:       i,
			PartyIDs:  partyIDs,
			Xi:        xj[i],
			BigXj:     BigXj,
			ECDSAPub:  pub,
			OT:        ot[i],
			ChainCode: chainCode,
		}
		if err := out[i].ValidateBasic(); err != nil {
			return nil, fmt.Errorf("dklstss: Keygen produced invalid key for party %d: %w", i, err)
		}
	}
	return out, nil
}

// deriveChainCode produces a 32-byte BIP32 chain code from the joint
// public key. Deterministic across parties; not a secret.
func deriveChainCode(pub *crypto.ECPoint) []byte {
	h := sha256.New()
	h.Write([]byte("DKLS23-chaincode-v1"))
	h.Write(pub.X().Bytes())
	h.Write([]byte{0x00})
	h.Write(pub.Y().Bytes())
	return h.Sum(nil)
}

// evaluateCommitmentSum returns Σ_i (commitments[i] evaluated at id) — a
// curve point equal to (Σ_i f_i(id)) · G where each f_i is the Feldman
// polynomial whose constant term is u_i.
//
// Per Feldman: a commitment Vs = [v_0, v_1, ..., v_t] with v_k = a_k · G
// implies f(id) · G = Σ_k id^k · v_k.
func evaluateCommitmentSum(ec elliptic.Curve, commitments []vss.Vs, id *big.Int) (*crypto.ECPoint, error) {
	q := ec.Params().N
	var result *crypto.ECPoint
	for i := range commitments {
		Vs := commitments[i]
		// Horner evaluate f_i(id) · G = ((... + v_t · id) + v_{t-1}) · id + ... + v_0
		// (using point operations: scalar-mult by id is the polynomial step).
		eval := Vs[len(Vs)-1]
		for k := len(Vs) - 2; k >= 0; k-- {
			scaled := eval.ScalarMult(new(big.Int).Mod(id, q))
			var err error
			eval, err = scaled.Add(Vs[k])
			if err != nil {
				return nil, fmt.Errorf("dklstss: evaluateCommitmentSum add: %w", err)
			}
		}
		if result == nil {
			result = eval
		} else {
			var err error
			result, err = result.Add(eval)
			if err != nil {
				return nil, fmt.Errorf("dklstss: evaluateCommitmentSum sum: %w", err)
			}
		}
	}
	return result, nil
}
