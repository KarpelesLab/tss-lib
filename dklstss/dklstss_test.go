package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// genPartyIDs returns n test PartyIDs with sequential keys 1..n.
func genPartyIDs(n int) tss.SortedPartyIDs {
	unsorted := make(tss.UnSortedPartyIDs, n)
	for i := 0; i < n; i++ {
		unsorted[i] = tss.NewPartyID(
			"id-"+string(rune('A'+i)),
			"moniker-"+string(rune('A'+i)),
			big.NewInt(int64(i+1)),
		)
	}
	return tss.SortPartyIDs(unsorted)
}

// TestKeygenBasic verifies that DKG produces consistent keys: all parties
// agree on the joint public key, and the Lagrange-reconstructed secret
// matches.
func TestKeygenBasic(t *testing.T) {
	const n, threshold = 3, 1
	ids := genPartyIDs(n)
	keys, err := Keygen(n, threshold, ids, rand.Reader)
	require.NoError(t, err)
	require.Len(t, keys, n)

	// All keys agree on the joint public key.
	pub := keys[0].ECDSAPub
	for i := 1; i < n; i++ {
		assert.Truef(t, pub.Equals(keys[i].ECDSAPub), "key %d has different ECDSAPub", i)
	}

	// All keys agree on the Big X_j commitments.
	for j := 0; j < n; j++ {
		for i := 1; i < n; i++ {
			assert.Truef(t, keys[0].BigXj[j].Equals(keys[i].BigXj[j]), "BigXj[%d] differs between key 0 and key %d", j, i)
		}
	}

	// Reconstruct the secret via Lagrange interpolation across any T+1
	// subset and verify it produces the joint public key.
	q := tss.S256().Params().N
	subsetIDs := []*big.Int{ids[0].KeyInt(), ids[1].KeyInt()}
	lam0, err := lagrangeCoefficient(q, subsetIDs, 0)
	require.NoError(t, err)
	lam1, err := lagrangeCoefficient(q, subsetIDs, 1)
	require.NoError(t, err)

	x := new(big.Int).Mul(lam0, keys[0].Xi)
	x.Add(x, new(big.Int).Mul(lam1, keys[1].Xi))
	x.Mod(x, q)

	// x · G should equal the joint public key.
	// (Computed via Lagrange at 0; matches the constant term of the joint polynomial.)
	xG := pub.Curve().Params()
	_ = xG
	gx, gy := pub.Curve().ScalarBaseMult(x.Bytes())
	assert.Equal(t, pub.X().String(), gx.String(), "reconstructed x · G x-coord")
	assert.Equal(t, pub.Y().String(), gy.String(), "reconstructed x · G y-coord")
}

// TestSignAndVerify is the main end-to-end test: DKG, then signing across
// a T+1 subset, then verification via stdlib crypto/ecdsa.
func TestSignAndVerify(t *testing.T) {
	cases := []struct {
		n, threshold int
		signers      []int
		label        string
	}{
		{n: 2, threshold: 1, signers: []int{0, 1}, label: "2-of-2"},
		{n: 3, threshold: 1, signers: []int{0, 1}, label: "2-of-3 (first two)"},
		{n: 3, threshold: 1, signers: []int{0, 2}, label: "2-of-3 (skip middle)"},
		{n: 3, threshold: 2, signers: []int{0, 1, 2}, label: "3-of-3"},
		{n: 4, threshold: 1, signers: []int{1, 3}, label: "2-of-4 mixed"},
		{n: 4, threshold: 2, signers: []int{0, 2, 3}, label: "3-of-4 mixed"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			ids := genPartyIDs(tc.n)
			keys, err := Keygen(tc.n, tc.threshold, ids, rand.Reader)
			require.NoError(t, err)

			msg := []byte("hello DKLs23 — " + tc.label)
			digest := sha256.Sum256(msg)
			sig, err := Sign(keys, tc.signers, digest[:], rand.Reader)
			require.NoError(t, err)
			require.NotNil(t, sig)
			require.NotNil(t, sig.R)
			require.NotNil(t, sig.S)

			// Verify with stdlib ecdsa.
			pub := &ecdsa.PublicKey{
				Curve: keys[0].ECDSAPub.Curve(),
				X:     keys[0].ECDSAPub.X(),
				Y:     keys[0].ECDSAPub.Y(),
			}
			ok := ecdsa.Verify(pub, digest[:], sig.R, sig.S)
			assert.Truef(t, ok, "%s: ecdsa.Verify failed (R=%s, S=%s)", tc.label, sig.R, sig.S)
		})
	}
}

// TestSignMultipleSubsets verifies that different signing subsets all
// produce signatures that verify under the SAME public key — i.e., the
// Lagrange coefficient scaling is consistent across subsets.
func TestSignMultipleSubsets(t *testing.T) {
	const n, threshold = 4, 2
	ids := genPartyIDs(n)
	keys, err := Keygen(n, threshold, ids, rand.Reader)
	require.NoError(t, err)
	msg := []byte("subset-test")
	digest := sha256.Sum256(msg)

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}

	subsets := [][]int{
		{0, 1, 2},
		{0, 1, 3},
		{0, 2, 3},
		{1, 2, 3},
	}
	for _, subset := range subsets {
		sig, err := Sign(keys, subset, digest[:], rand.Reader)
		require.NoError(t, err)
		ok := ecdsa.Verify(pub, digest[:], sig.R, sig.S)
		assert.Truef(t, ok, "subset %v signature failed verification", subset)
	}
}

// TestSignRandomMessages stresses signing with many random messages to
// catch corner cases in nonce handling.
func TestSignRandomMessages(t *testing.T) {
	const n, threshold = 3, 1
	ids := genPartyIDs(n)
	keys, err := Keygen(n, threshold, ids, rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}

	for trial := 0; trial < 5; trial++ {
		var msg [32]byte
		_, err := rand.Read(msg[:])
		require.NoError(t, err)
		signers := []int{0, 1}
		if trial%2 == 1 {
			signers = []int{1, 2}
		}
		sig, err := Sign(keys, signers, msg[:], rand.Reader)
		require.NoError(t, err)
		require.Truef(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S), "trial %d: signature failed", trial)
	}
}

// TestSignLowSNormalization verifies that S is always ≤ q/2 (BIP-62).
func TestSignLowSNormalization(t *testing.T) {
	const n, threshold = 2, 1
	ids := genPartyIDs(n)
	keys, err := Keygen(n, threshold, ids, rand.Reader)
	require.NoError(t, err)
	q := tss.S256().Params().N
	halfQ := new(big.Int).Rsh(q, 1)

	for trial := 0; trial < 8; trial++ {
		var msg [32]byte
		_, err := rand.Read(msg[:])
		require.NoError(t, err)
		sig, err := Sign(keys, []int{0, 1}, msg[:], rand.Reader)
		require.NoError(t, err)
		assert.Truef(t, sig.S.Cmp(halfQ) <= 0, "trial %d: S > q/2 (low-S normalization failed)", trial)
	}
}

// TestSignErrorPaths exercises malformed-input rejections.
func TestSignErrorPaths(t *testing.T) {
	const n, threshold = 3, 1
	ids := genPartyIDs(n)
	keys, err := Keygen(n, threshold, ids, rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("test"))

	// Empty keys.
	_, err = Sign(nil, []int{0, 1}, digest[:], rand.Reader)
	require.Error(t, err)

	// Wrong number of signers.
	_, err = Sign(keys, []int{0}, digest[:], rand.Reader)
	require.Error(t, err)
	_, err = Sign(keys, []int{0, 1, 2}, digest[:], rand.Reader)
	require.Error(t, err)

	// Out-of-range signer index.
	_, err = Sign(keys, []int{0, 99}, digest[:], rand.Reader)
	require.Error(t, err)

	// Duplicate signer index.
	_, err = Sign(keys, []int{0, 0}, digest[:], rand.Reader)
	require.Error(t, err)

	// Empty hash.
	_, err = Sign(keys, []int{0, 1}, nil, rand.Reader)
	require.Error(t, err)
}
