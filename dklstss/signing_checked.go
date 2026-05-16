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
	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// SignChecked is the malicious-secure variant of Sign: every cross-term
// ΠMul invocation uses the Mul-then-check pattern from
// crypto/ot/ole.CheckedMul. If a peer deviates between the two
// parallel multiplications, the protocol aborts and returns a
// *tss.Error whose Culprits() identifies the deviating peer.
//
// Cost: roughly 2× the wire and CPU cost of Sign because every ΠMul
// runs twice in parallel.
func SignChecked(keys []*Key, signerIdx []int, hash []byte, rng io.Reader) (*Signature, error) {
	return signCheckedCore(keys, signerIdx, nil, hash, rng)
}

// SignCheckedWithTweak is SignChecked with an optional HD tweak,
// analogous to SignWithTweak.
func SignCheckedWithTweak(keys []*Key, signerIdx []int, tweak *big.Int, hash []byte, rng io.Reader) (*Signature, error) {
	return signCheckedCore(keys, signerIdx, tweak, hash, rng)
}

// signCheckedCore is the shared implementation; tweak is optional.
func signCheckedCore(keys []*Key, signerIdx []int, tweak *big.Int, hash []byte, rng io.Reader) (*Signature, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if len(keys) == 0 {
		return nil, errors.New("dklstss: SignChecked requires at least one key")
	}
	n := keys[0].N
	t := keys[0].T
	pub := keys[0].ECDSAPub
	if len(signerIdx) != t+1 {
		return nil, fmt.Errorf("dklstss: SignChecked requires T+1=%d signers, got %d", t+1, len(signerIdx))
	}
	seen := make(map[int]struct{}, len(signerIdx))
	for _, idx := range signerIdx {
		if idx < 0 || idx >= n {
			return nil, fmt.Errorf("dklstss: SignChecked signerIdx %d out of range", idx)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("dklstss: SignChecked duplicate signerIdx %d", idx)
		}
		seen[idx] = struct{}{}
	}
	if len(hash) == 0 {
		return nil, errors.New("dklstss: SignChecked hash must be non-empty")
	}
	ec := tss.S256()
	q := ec.Params().N

	sgn := len(signerIdx)
	signers := make([]*Key, sgn)
	for i, idx := range signerIdx {
		signers[i] = keys[idx]
		if signers[i].N != n || signers[i].T != t || !signers[i].ECDSAPub.Equals(pub) {
			return nil, fmt.Errorf("dklstss: SignChecked key %d inconsistent", idx)
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
			return nil, fmt.Errorf("dklstss: SignChecked lagrange: %w", err)
		}
		lambdas[i] = lam
	}
	sx := make([]*big.Int, sgn)
	for i := range signers {
		sx[i] = new(big.Int).Mul(lambdas[i], signers[i].Xi)
		sx[i].Mod(sx[i], q)
	}
	if tweak != nil {
		ttw := new(big.Int).Mod(tweak, q)
		sx[0] = new(big.Int).Add(sx[0], ttw)
		sx[0].Mod(sx[0], q)
	}

	var ssidNonce [16]byte
	if _, err := io.ReadFull(rng, ssidNonce[:]); err != nil {
		return nil, fmt.Errorf("dklstss: SignChecked ssid: %w", err)
	}
	ssid := make([]byte, 0, 32+len(hash))
	ssid = append(ssid, []byte("DKLS23-signchecked-v1-")...)
	ssid = append(ssid, ssidNonce[:]...)
	ssid = append(ssid, '|')
	ssid = append(ssid, hash...)

	k := make([]*big.Int, sgn)
	rho := make([]*big.Int, sgn)
	Ki := make([]*crypto.ECPoint, sgn)
	for i := range signers {
		k[i] = common.GetRandomPositiveInt(rng, q)
		rho[i] = common.GetRandomPositiveInt(rng, q)
		Ki[i] = ctmul.ScalarBaseMultWithRand(ec, k[i], rng)
	}
	R := Ki[0]
	for i := 1; i < sgn; i++ {
		var err error
		R, err = R.Add(Ki[i])
		if err != nil {
			return nil, fmt.Errorf("dklstss: SignChecked R aggregation: %w", err)
		}
	}
	r := new(big.Int).Mod(R.X(), q)
	if r.Sign() == 0 {
		return nil, errors.New("dklstss: SignChecked R.X is 0 mod q; retry")
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
				return nil, fmt.Errorf("dklstss: SignChecked missing OT state between %d and %d",
					aliceKey.Idx, bobKey.Idx)
			}

			bobPID := bobKey.PartyIDs[bobKey.Idx]
			// k_i · ρ_j with Mul-then-check.
			if err := runCheckedMul(
				makeSid(ssid, "signchecked-kxrho", aliceKey.Idx, bobKey.Idx),
				alicePair.AsAlice, bobPair.AsBob,
				k[ai], rho[bj],
				kRhoShare, ai, bj, bobPID,
			); err != nil {
				return nil, err
			}

			// x_i · ρ_j with Mul-then-check.
			if err := runCheckedMul(
				makeSid(ssid, "signchecked-xxrho", aliceKey.Idx, bobKey.Idx),
				alicePair.AsAlice, bobPair.AsBob,
				sx[ai], rho[bj],
				xRhoShare, ai, bj, bobPID,
			); err != nil {
				return nil, err
			}
		}
	}

	phi := new(big.Int)
	for _, v := range kRhoShare {
		phi.Add(phi, v)
		phi.Mod(phi, q)
	}
	if phi.Sign() == 0 {
		return nil, errors.New("dklstss: SignChecked φ is 0; retry")
	}
	hashI := new(big.Int).SetBytes(hash)
	hashI.Mod(hashI, q)
	sigmaSum := new(big.Int)
	for i := range signers {
		t1 := new(big.Int).Mul(rho[i], hashI)
		t1.Mod(t1, q)
		t2 := new(big.Int).Mul(r, xRhoShare[i])
		t2.Mod(t2, q)
		shati := new(big.Int).Add(t1, t2)
		shati.Mod(shati, q)
		sigmaSum.Add(sigmaSum, shati)
		sigmaSum.Mod(sigmaSum, q)
	}
	phiInv := common.ModInt(q).ModInverse(phi)
	if phiInv == nil {
		return nil, errors.New("dklstss: SignChecked φ has no inverse")
	}
	s := new(big.Int).Mul(sigmaSum, phiInv)
	s.Mod(s, q)
	if s.Sign() == 0 {
		return nil, errors.New("dklstss: SignChecked produced s=0; retry")
	}
	halfQ := new(big.Int).Rsh(q, 1)
	v := byte(R.Y().Bit(0))
	if s.Cmp(halfQ) > 0 {
		s.Sub(q, s)
		v ^= 1
	}
	return &Signature{R: r, S: s, V: v}, nil
}

// runCheckedMul wraps a single (alpha, beta) ΠMul-with-check between
// Alice (party ai) and Bob (party bj). On success, adds Alice's share
// to shares[ai] and Bob's share to shares[bj]. On failure, wraps the
// Mul-then-check error in a *tss.Error with Culprits set to Bob's
// party ID (cross-run β inconsistency = Bob deviated).
func runCheckedMul(
	sid []byte,
	aliceReceiver *otext.ExtReceiver,
	bobSender *otext.ExtSender,
	alpha, beta *big.Int,
	shares []*big.Int,
	ai, bj int,
	bobPartyID *tss.PartyID,
) error {
	msg1, msg2, state, err := ole.CheckedAliceStep1(sid, aliceReceiver, alpha)
	if err != nil {
		return fmt.Errorf("dklstss: SignChecked ΠMul Alice1: %w", err)
	}
	bMsg, uB, err := ole.CheckedBobStep1(sid, bobSender, beta, msg1, msg2)
	if err != nil {
		return fmt.Errorf("dklstss: SignChecked ΠMul Bob: %w", err)
	}
	uA, err := ole.CheckedAliceStep2(state, bMsg)
	if err != nil {
		// Mul-then-check failure — Bob deviated. Wrap in tss.Error
		// with Bob's party ID as the culprit.
		return tss.NewError(err, "dklstss-sign-checked", 0, nil, bobPartyID)
	}
	q := tss.S256().Params().N
	shares[ai] = addMod(q, shares[ai], uA)
	shares[bj] = addMod(q, shares[bj], uB)
	return nil
}
