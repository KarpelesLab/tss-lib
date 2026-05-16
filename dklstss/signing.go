package dklstss

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ctmul"
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/ole"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Sign runs the threshold-ECDSA signing protocol synchronously in-process
// across the given signing subset. Returns a standard ECDSA signature
// that verifies under keys[*].ECDSAPub.
//
// signerIdx specifies the T+1 party indexes that participate; entries
// must be distinct and in range [0, N).
//
// hash is the message digest (already hashed, e.g. SHA-256 output for
// secp256k1+ECDSA). It is reduced mod q before use.
func Sign(keys []*Key, signerIdx []int, hash []byte, rng io.Reader) (*Signature, error) {
	return signCore(keys, signerIdx, nil, hash, rng)
}

// SignWithTweak signs as Sign does but adds `tweak` to the effective
// private key. This is used by HD derivation (BIP32): a non-hardened
// child private key equals (parent_priv + tweak) mod q for a publicly
// computable tweak. The tweak is absorbed into the first signer's
// effective share by convention.
//
// The caller is responsible for computing the matching child public key
// (parent_pub + tweak · G) and passing it to the verifier.
func SignWithTweak(keys []*Key, signerIdx []int, tweak *big.Int, hash []byte, rng io.Reader) (*Signature, error) {
	return signCore(keys, signerIdx, tweak, hash, rng)
}

// signCore is the shared signing implementation accepting an optional
// tweak. When non-nil, tweak is added to the effective share of the first
// signer (signers[0]), making the joint signing key equal
// (parent_secret + tweak) mod q.
func signCore(keys []*Key, signerIdx []int, tweak *big.Int, hash []byte, rng io.Reader) (*Signature, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if len(keys) == 0 {
		return nil, errors.New("dklstss: Sign requires at least one key")
	}
	n := keys[0].N
	t := keys[0].T
	pub := keys[0].ECDSAPub
	if len(signerIdx) != t+1 {
		return nil, fmt.Errorf("dklstss: Sign requires T+1=%d signers, got %d", t+1, len(signerIdx))
	}
	seen := make(map[int]struct{}, len(signerIdx))
	for _, idx := range signerIdx {
		if idx < 0 || idx >= n {
			return nil, fmt.Errorf("dklstss: Sign signerIdx %d out of range [0,%d)", idx, n)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("dklstss: Sign duplicate signerIdx %d", idx)
		}
		seen[idx] = struct{}{}
	}
	if len(hash) == 0 {
		return nil, errors.New("dklstss: Sign hash must be non-empty")
	}
	ec := tss.S256()
	q := ec.Params().N

	// Resolve signing subset.
	sgn := len(signerIdx)
	signers := make([]*Key, sgn)
	for i, idx := range signerIdx {
		signers[i] = keys[idx]
		if signers[i].N != n || signers[i].T != t || !signers[i].ECDSAPub.Equals(pub) {
			return nil, fmt.Errorf("dklstss: Sign key %d inconsistent with first key", idx)
		}
	}

	// Lagrange coefficients for subset evaluation at x=0.
	ids := make([]*big.Int, sgn)
	for i, k := range signers {
		ids[i] = k.PartyIDs[k.Idx].KeyInt()
	}
	lambdas := make([]*big.Int, sgn)
	for i := range signers {
		lam, err := lagrangeCoefficient(q, ids, i)
		if err != nil {
			return nil, fmt.Errorf("dklstss: Sign lagrange: %w", err)
		}
		lambdas[i] = lam
	}

	// Effective signing share per party: s_x_i = λ_i · x_i mod q.
	sx := make([]*big.Int, sgn)
	for i := range signers {
		sx[i] = new(big.Int).Mul(lambdas[i], signers[i].Xi)
		sx[i].Mod(sx[i], q)
	}
	// HD tweak: add the public tweak to the first signer's effective share.
	// Convention: signers[0] (the first index in signerIdx) absorbs the tweak;
	// others are unchanged. Σ sx + tweak = (parent_secret + tweak) mod q.
	if tweak != nil {
		t := new(big.Int).Mod(tweak, q)
		sx[0] = new(big.Int).Add(sx[0], t)
		sx[0].Mod(sx[0], q)
	}

	// Fresh per-Sign session id, bound to message digest.
	var ssidNonce [16]byte
	if _, err := io.ReadFull(rng, ssidNonce[:]); err != nil {
		return nil, fmt.Errorf("dklstss: Sign ssid nonce: %w", err)
	}
	ssid := make([]byte, 0, 32+len(hash))
	ssid = append(ssid, []byte("DKLS23-sign-v1-")...)
	ssid = append(ssid, ssidNonce[:]...)
	ssid = append(ssid, '|')
	ssid = append(ssid, hash...)

	// Round 1: each party samples k_i, ρ_i; broadcasts K_i = k_i · G.
	k := make([]*big.Int, sgn)
	rho := make([]*big.Int, sgn)
	Ki := make([]*crypto.ECPoint, sgn)
	for i := range signers {
		k[i] = common.GetRandomPositiveInt(rng, q)
		rho[i] = common.GetRandomPositiveInt(rng, q)
		// Route nonce-by-G through the constant-time scalar-mult.
		// k_i is the ECDSA nonce share; leaking it leaks the signing key.
		Ki[i] = ctmul.ScalarBaseMultWithRand(ec, k[i], rng)
	}

	// R = Σ K_i ; r = R.x mod q. (Reject r = 0; vanishingly unlikely.)
	R := Ki[0]
	for i := 1; i < sgn; i++ {
		var err error
		R, err = R.Add(Ki[i])
		if err != nil {
			return nil, fmt.Errorf("dklstss: Sign R aggregation: %w", err)
		}
	}
	r := new(big.Int).Mod(R.X(), q)
	if r.Sign() == 0 {
		return nil, errors.New("dklstss: Sign R.X is 0 mod q; retry with fresh randomness")
	}

	// Round 2: pairwise ΠMul to additive-share k·ρ and x·ρ cross-terms.
	//
	// For each ordered (i, j) with i ≠ j, party i (Alice) brings α and
	// party j (Bob) brings β. We invoke ΠMul once per (alpha, beta, kind)
	// triple. Two "kinds": k for (k_i, ρ_j), x for (s_x_i, ρ_j).
	//
	// Per-party accumulators:
	//   kRhoShare[i] = k_i·ρ_i + Σ_{j≠i} (α-share when i is Alice + β-share when i is Bob)
	//   xRhoShare[i] = s_x_i·ρ_i + Σ_{j≠i} (...)
	kRhoShare := make([]*big.Int, sgn)
	xRhoShare := make([]*big.Int, sgn)
	for i := range signers {
		// Diagonal terms: own k_i · ρ_i and s_x_i · ρ_i.
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
			// AliceKey.OT[bobKey.Idx].AsAlice and bobKey.OT[aliceKey.Idx].AsBob.
			alicePair := aliceKey.OT[bobKey.Idx]
			bobPair := bobKey.OT[aliceKey.Idx]
			if alicePair == nil || bobPair == nil {
				return nil, fmt.Errorf("dklstss: Sign missing OT state between party %d and %d", aliceKey.Idx, bobKey.Idx)
			}

			// ΠMul on (k_i, ρ_j).
			sidK := makeSid(ssid, "kxrho", aliceKey.Idx, bobKey.Idx)
			aMsgK, aStateK, err := ole.AliceStep1(sidK, alicePair.AsAlice, k[ai])
			if err != nil {
				return nil, fmt.Errorf("dklstss: Sign ΠMul-k Alice1 (i=%d,j=%d): %w", aliceKey.Idx, bobKey.Idx, err)
			}
			bMsgK, uBK, err := ole.BobStep1(sidK, bobPair.AsBob, rho[bj], aMsgK)
			if err != nil {
				return nil, fmt.Errorf("dklstss: Sign ΠMul-k Bob1 (i=%d,j=%d): %w", aliceKey.Idx, bobKey.Idx, err)
			}
			uAK, err := ole.AliceStep2(aStateK, bMsgK)
			if err != nil {
				return nil, fmt.Errorf("dklstss: Sign ΠMul-k Alice2 (i=%d,j=%d): %w", aliceKey.Idx, bobKey.Idx, err)
			}
			// Alice (party ai) accumulates uAK; Bob (party bj) accumulates uBK.
			kRhoShare[ai] = addMod(q, kRhoShare[ai], uAK)
			kRhoShare[bj] = addMod(q, kRhoShare[bj], uBK)

			// ΠMul on (s_x_i, ρ_j).
			sidX := makeSid(ssid, "xxrho", aliceKey.Idx, bobKey.Idx)
			aMsgX, aStateX, err := ole.AliceStep1(sidX, alicePair.AsAlice, sx[ai])
			if err != nil {
				return nil, fmt.Errorf("dklstss: Sign ΠMul-x Alice1 (i=%d,j=%d): %w", aliceKey.Idx, bobKey.Idx, err)
			}
			bMsgX, uBX, err := ole.BobStep1(sidX, bobPair.AsBob, rho[bj], aMsgX)
			if err != nil {
				return nil, fmt.Errorf("dklstss: Sign ΠMul-x Bob1 (i=%d,j=%d): %w", aliceKey.Idx, bobKey.Idx, err)
			}
			uAX, err := ole.AliceStep2(aStateX, bMsgX)
			if err != nil {
				return nil, fmt.Errorf("dklstss: Sign ΠMul-x Alice2 (i=%d,j=%d): %w", aliceKey.Idx, bobKey.Idx, err)
			}
			xRhoShare[ai] = addMod(q, xRhoShare[ai], uAX)
			xRhoShare[bj] = addMod(q, xRhoShare[bj], uBX)
		}
	}

	// Round 3a: reveal φ = Σ kRhoShare = k · ρ.
	phi := new(big.Int)
	for i := range signers {
		phi.Add(phi, kRhoShare[i])
		phi.Mod(phi, q)
	}
	if phi.Sign() == 0 {
		return nil, errors.New("dklstss: Sign φ = k·ρ is 0; retry with fresh randomness")
	}

	// Round 3b: each party computes ŝ_i = ρ_i · H(m) + r · σ_i mod q, reveal.
	hashI := new(big.Int).SetBytes(hash)
	hashI.Mod(hashI, q)
	sigmaSum := new(big.Int)
	for i := range signers {
		term1 := new(big.Int).Mul(rho[i], hashI)
		term1.Mod(term1, q)
		term2 := new(big.Int).Mul(r, xRhoShare[i])
		term2.Mod(term2, q)
		shati := new(big.Int).Add(term1, term2)
		shati.Mod(shati, q)
		sigmaSum.Add(sigmaSum, shati)
		sigmaSum.Mod(sigmaSum, q)
	}

	// s = ŝ · φ^{-1} mod q.
	phiInv := common.ModInt(q).ModInverse(phi)
	if phiInv == nil {
		return nil, errors.New("dklstss: Sign φ has no inverse")
	}
	s := new(big.Int).Mul(sigmaSum, phiInv)
	s.Mod(s, q)
	if s.Sign() == 0 {
		return nil, errors.New("dklstss: Sign produced s=0; retry")
	}

	// Low-S normalization (BIP-62): if s > q/2, replace with q - s.
	halfQ := new(big.Int).Rsh(q, 1)
	v := byte(R.Y().Bit(0))
	if s.Cmp(halfQ) > 0 {
		s.Sub(q, s)
		v ^= 1
	}

	return &Signature{R: r, S: s, V: v}, nil
}

// addMod returns (a + b) mod q.
func addMod(q, a, b *big.Int) *big.Int {
	out := new(big.Int).Add(a, b)
	out.Mod(out, q)
	return out
}

// makeSid composes a per-ΠMul sid bound to the signing session and the
// (alice, bob, kind) triple. Each invocation produces a distinct sid so
// the OT extension's challenge derivation is freshly bound.
//
// alice and bob are encoded as length-prefixed big-endian 4-byte values
// rather than raw bytes — the previous `byte(alice), byte(bob)` form
// truncated indexes silently, so a 256-party setup would collide sids
// across pairs whose low bytes matched. With 4-byte encoding the
// encoding is injective up to 2^32 parties, far past any practical TSS.
func makeSid(ssid []byte, kind string, alice, bob int) []byte {
	out := make([]byte, 0, len(ssid)+len(kind)+11)
	out = append(out, ssid...)
	out = append(out, '|')
	out = append(out, kind...)
	out = append(out, '|')
	out = append(out,
		byte(alice>>24), byte(alice>>16), byte(alice>>8), byte(alice),
		'|',
		byte(bob>>24), byte(bob>>16), byte(bob>>8), byte(bob),
	)
	return out
}
