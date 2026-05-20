// Copyright © 2026 KarpelesLab.

package dklstss

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// noopStore counts CheckAndRecord invocations. Returns (true, nil) by
// default so the inner SignWithPresign call is reached. Used to assert
// that SignWithPresignDurable rejects empty hashes BEFORE touching
// the store.
type noopStore struct {
	hits int
}

func (s *noopStore) CheckAndRecord(rHash []byte) (bool, error) {
	s.hits++
	return true, nil
}

// TestSignWithPresignDurableRejectsEmptyHashBeforeStore confirms the
// audit fix: an empty hash short-circuits with an error BEFORE the
// durable store is consulted, so a caller misuse does not burn an R-
// hash slot in the backing store.
func TestSignWithPresignDurableRejectsEmptyHashBeforeStore(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	presign, err := Presign(keys, []int{0, 1}, nil)
	require.NoError(t, err)

	store := &noopStore{}
	_, err = SignWithPresignDurable(presign, []byte{}, nil, store)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty hash")
	require.Equal(t, 0, store.hits, "store must NOT be consulted on empty hash")
}

// TestLoadRejectsNonSecp256k1Curve confirms the audit fix: a saved Key
// claiming a non-secp256k1 curve is rejected at Load.
func TestLoadRejectsNonSecp256k1Curve(t *testing.T) {
	// Hand-craft a v4 payload with curve="ed25519".
	wire := map[string]any{
		"format":  keyFormatMagic,
		"version": KeyWireVersion,
		"curve":   "ed25519",
	}
	buf, err := json.Marshal(wire)
	require.NoError(t, err)
	_, err = Load(bytes.NewReader(buf))
	require.Error(t, err)
	require.Contains(t, err.Error(), "secp256k1")
}

// TestLoadRejectsMissingFormatMagic confirms the audit fix: a v4+
// payload missing the Format magic field is rejected.
func TestLoadRejectsMissingFormatMagic(t *testing.T) {
	wire := map[string]any{
		"version": KeyWireVersion,
		"curve":   "secp256k1",
	}
	buf, err := json.Marshal(wire)
	require.NoError(t, err)
	_, err = Load(bytes.NewReader(buf))
	require.Error(t, err)
	require.Contains(t, err.Error(), "format magic")
}

// TestLoadAcceptsLegacyV1V2V3WithoutFormatMagic confirms the loader
// still accepts pre-v4 payloads that have no Format field.
func TestLoadAcceptsLegacyV1V2V3WithoutFormatMagic(t *testing.T) {
	for _, v := range []uint32{1, 2, 3} {
		// We only verify the version + curve check passes; the rest
		// of the payload is intentionally invalid so it fails further
		// down with a non-curve, non-magic error. That's enough to
		// prove the gate didn't fire on the magic check.
		wire := map[string]any{
			"version": v,
			"curve":   "secp256k1",
		}
		buf, err := json.Marshal(wire)
		require.NoError(t, err)
		_, err = Load(bytes.NewReader(buf))
		require.Error(t, err)
		require.NotContains(t, err.Error(), "format magic",
			"v%d payload must not be rejected on magic check", v)
	}
}
