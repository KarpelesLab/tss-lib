package dklstss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestHashToScalar32ByteMatchesLegacy verifies that for a 32-byte digest
// on secp256k1, hashToScalar produces the same value as the legacy
// `SetBytes(hash).Mod(q)` form. This guards against accidentally
// regressing the standard SHA-256 case.
func TestHashToScalar32ByteMatchesLegacy(t *testing.T) {
	q := tss.S256().Params().N
	for i := 0; i < 32; i++ {
		hash := make([]byte, 32)
		_, err := rand.Read(hash)
		require.NoError(t, err)

		got := hashToScalar(q, hash)

		legacy := new(big.Int).SetBytes(hash)
		legacy.Mod(legacy, q)

		require.Zero(t, got.Cmp(legacy), "32-byte hash should match legacy formulation")
	}
}

// TestHashToScalar64ByteUsesLeftmostBits verifies that for a 64-byte
// (SHA-512) digest on secp256k1, hashToScalar takes the leftmost 256 bits
// rather than the full 512-bit value reduced mod q. This matches SEC 1
// §4.1.3 and crypto/ecdsa.Verify, so a signature produced via this scalar
// is verifiable by stdlib code.
func TestHashToScalar64ByteUsesLeftmostBits(t *testing.T) {
	q := tss.S256().Params().N
	hash := make([]byte, 64)
	_, err := rand.Read(hash)
	require.NoError(t, err)

	got := hashToScalar(q, hash)

	// Expected: top 256 bits of `hash` interpreted as big-endian, mod q.
	top := new(big.Int).SetBytes(hash[:32])
	top.Mod(top, q)
	require.Zero(t, got.Cmp(top), "64-byte hash should reduce via leftmost 256 bits")

	// Diverges from the legacy form (which reduces the full 512-bit value).
	legacy := new(big.Int).SetBytes(hash)
	legacy.Mod(legacy, q)
	require.NotZero(t, got.Cmp(legacy), "64-byte hash form must diverge from buggy legacy")
}

// TestSignWithSHA512HashRoundTripsThroughStdlib is the end-to-end
// regression: produce a signature via dklstss.Sign on a SHA-512 (64-byte)
// digest, then verify with crypto/ecdsa.Verify on the same digest.
// Before the hashToScalar fix the second step failed.
func TestSignWithSHA512HashRoundTripsThroughStdlib(t *testing.T) {
	const N, T = 3, 1
	partyIDs := genPartyIDs(N)
	keys, err := Keygen(N, T, partyIDs, rand.Reader)
	require.NoError(t, err)

	digest := sha512.Sum512([]byte("threshold sign me through a 64-byte digest"))

	sig, err := Sign(keys, []int{0, 2}, digest[:], rand.Reader)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	// crypto/ecdsa.Verify itself applies the SEC 1 truncation rule to the
	// supplied digest. The signature must verify.
	ok := ecdsa.Verify(pub, digest[:], sig.R, sig.S)
	require.True(t, ok, "SHA-512 digest signed via Sign must verify via stdlib ECDSA")
}

// TestSignWithPresignSHA512RoundTrip mirrors the above for the
// SignWithPresign path.
func TestSignWithPresignSHA512RoundTrip(t *testing.T) {
	const N, T = 3, 1
	partyIDs := genPartyIDs(N)
	keys, err := Keygen(N, T, partyIDs, rand.Reader)
	require.NoError(t, err)

	presign, err := Presign(keys, []int{0, 2}, rand.Reader)
	require.NoError(t, err)

	digest := sha512.Sum512([]byte("presign sign me through a 64-byte digest"))
	sig, err := SignWithPresign(presign, digest[:], nil)
	require.NoError(t, err)

	pub := &ecdsa.PublicKey{
		Curve: keys[0].ECDSAPub.Curve(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	ok := ecdsa.Verify(pub, digest[:], sig.R, sig.S)
	require.True(t, ok, "SHA-512 digest signed via SignWithPresign must verify via stdlib")
}
