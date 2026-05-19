package dklstss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestImportKeyAndReshareRoundTrip is the headline test: take a plain
// secp256k1 ECDSA private key, import it as a 1-of-1 dklstss Key, run
// Reshare into a t-of-n committee, then sign with the new committee
// under the ORIGINAL public key. This is the migration path advertised
// in the package doc.
func TestImportKeyAndReshareRoundTrip(t *testing.T) {
	// Generate a stdlib ECDSA key on secp256k1.
	priv := new(ecdsa.PrivateKey)
	priv.Curve = secp256k1.S256()
	d, err := rand.Int(rand.Reader, priv.Curve.Params().N)
	require.NoError(t, err)
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(d.Bytes())

	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))

	oldKey, err := ImportKey(priv, importer)
	require.NoError(t, err)
	require.NoError(t, oldKey.ValidateBasic())
	require.Equal(t, 0, priv.PublicKey.X.Cmp(oldKey.ECDSAPub.X()))
	require.Equal(t, 0, priv.PublicKey.Y.Cmp(oldKey.ECDSAPub.Y()))

	// Build a fresh new committee.
	const newN, newT = 5, 2
	newIDs := genPartyIDs(newN)

	newKeys, err := Reshare([]*Key{oldKey}, []int{0}, newIDs, newT, rand.Reader)
	require.NoError(t, err)
	require.Len(t, newKeys, newN)

	// Public key preserved across the entire committee.
	for i, k := range newKeys {
		require.Truef(t, k.ECDSAPub.Equals(oldKey.ECDSAPub),
			"new key %d: ECDSAPub differs from original", i)
	}

	// Sign with a T+1 subset and verify under the original pubkey via
	// the stdlib verifier.
	msg := sha256.Sum256([]byte("import-and-reshare round trip"))
	sig, err := Sign(newKeys, []int{0, 1, 2}, msg[:], rand.Reader)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: newKeys[0].ECDSAPub.Curve(),
		X:     newKeys[0].ECDSAPub.X(),
		Y:     newKeys[0].ECDSAPub.Y(),
	}
	require.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S),
		"imported-key signature must verify under stdlib ECDSA")
}

// TestImportKeyCanonicalChainCode confirms the chain code on the imported
// key matches what dklstss.Keygen would have produced for the same pub.
// Without this, BIP32 non-hardened derivation post-import diverges from
// any external wallet's view.
func TestImportKeyCanonicalChainCode(t *testing.T) {
	priv := new(ecdsa.PrivateKey)
	priv.Curve = secp256k1.S256()
	priv.D = big.NewInt(0x1234567890)
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(priv.D.Bytes())

	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))
	k, err := ImportKey(priv, importer)
	require.NoError(t, err)

	// Recompute the canonical chain code via the (unexported) helper,
	// reachable since this test is in the same package.
	want := deriveChainCode(k.ECDSAPub)
	require.Equal(t, want, k.ChainCode)
}

// TestImportKeyRejectsMismatchedPubKey verifies the safety check: if the
// caller passes a private key whose declared PublicKey doesn't match
// priv.D · G, ImportKey rejects before resharing exposes the
// inconsistency through indirect failure modes.
func TestImportKeyRejectsMismatchedPubKey(t *testing.T) {
	priv := new(ecdsa.PrivateKey)
	priv.Curve = secp256k1.S256()
	priv.D = big.NewInt(7)
	// Intentionally wrong PublicKey.
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(big.NewInt(8).Bytes())

	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))
	_, err := ImportKey(priv, importer)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
}

// TestImportKeyRejectsZeroAndNil covers the input-validation surface.
func TestImportKeyRejectsZeroAndNil(t *testing.T) {
	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))

	_, err := ImportKey(nil, importer)
	require.Error(t, err)

	zero := new(ecdsa.PrivateKey)
	zero.Curve = secp256k1.S256()
	zero.D = big.NewInt(0)
	_, err = ImportKey(zero, importer)
	require.Error(t, err)
	require.Contains(t, err.Error(), "zero")
}

// TestImportKeyRejectsWrongCurve confirms a P-256 key is rejected with a
// clear curve-mismatch error.
func TestImportKeyRejectsWrongCurve(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))
	_, err = ImportKey(p256, importer)
	require.Error(t, err)
	require.Contains(t, err.Error(), "secp256k1")
}
