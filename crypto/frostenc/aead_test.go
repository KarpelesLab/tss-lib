// Copyright © 2026 KarpelesLab.

package frostenc

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealOpenRoundTrip(t *testing.T) {
	priv1, pub1, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)
	priv2, pub2, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)

	ad := []byte("session-id-12345||sender:1||recipient:2||label:keygen-r2")
	pt := []byte("the secret share scalar bytes")

	ct, err := SealShare(rand.Reader, priv1, pub2, ad, pt)
	require.NoError(t, err)
	require.NotEqual(t, pt, ct)

	got, err := OpenShare(priv2, pub1, ad, ct)
	require.NoError(t, err)
	require.Equal(t, pt, got)
}

func TestOpenWithWrongPrivFails(t *testing.T) {
	priv1, _, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)
	_, pub2, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)
	priv3, _, err := NewEphemeralKey(rand.Reader) // wrong recipient
	require.NoError(t, err)

	ad := []byte("ad")
	ct, err := SealShare(rand.Reader, priv1, pub2, ad, []byte("plaintext"))
	require.NoError(t, err)

	// Open with priv3 (not priv2) must fail.
	_, err = OpenShare(priv3, pub2, ad, ct)
	require.Error(t, err)
}

func TestOpenWithWrongADFails(t *testing.T) {
	priv1, pub1, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)
	priv2, pub2, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)

	ct, err := SealShare(rand.Reader, priv1, pub2, []byte("ad1"), []byte("plaintext"))
	require.NoError(t, err)

	_, err = OpenShare(priv2, pub1, []byte("ad2-different"), ct)
	require.Error(t, err)
}

func TestSealRejectsBadInputs(t *testing.T) {
	priv, pub, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)

	_, err = SealShare(rand.Reader, priv[:31], pub, nil, nil)
	require.Error(t, err)
	_, err = SealShare(rand.Reader, priv, pub[:31], nil, nil)
	require.Error(t, err)
	_, err = SealShare(nil, priv, pub, nil, nil)
	require.Error(t, err)
}

func TestOpenRejectsBadInputs(t *testing.T) {
	priv, pub, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)

	_, err = OpenShare(priv[:31], pub, nil, make([]byte, 100))
	require.Error(t, err)
	_, err = OpenShare(priv, pub[:31], nil, make([]byte, 100))
	require.Error(t, err)
	_, err = OpenShare(priv, pub, nil, make([]byte, SealedNonceBytes)) // too short
	require.Error(t, err)
}

func TestSealRejectsSmallSubgroup(t *testing.T) {
	priv1, _, err := NewEphemeralKey(rand.Reader)
	require.NoError(t, err)
	// All-zero pub triggers the small-subgroup rejection path. The
	// standard library's curve25519 catches "low order point" before
	// our own "all-zero" defense fires — accept either.
	zeroPub := make([]byte, EphemeralKeyBytes)
	_, err = SealShare(rand.Reader, priv1, zeroPub, nil, []byte("plaintext"))
	require.Error(t, err)
}
