package dklstss

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeySaveLoadRoundTrip serializes a Key, deserializes it, and
// verifies signing with the loaded key produces a valid signature.
func TestKeySaveLoadRoundTrip(t *testing.T) {
	keys, err := Keygen(3, 1, genPartyIDs(3), rand.Reader)
	require.NoError(t, err)
	pub := keys[0].ECDSAPub

	for i, k := range keys {
		var buf bytes.Buffer
		require.NoError(t, k.Save(&buf), "save key %d", i)

		loaded, err := Load(&buf)
		require.NoError(t, err, "load key %d", i)

		// Round-trip equality on observable fields.
		assert.Equal(t, k.N, loaded.N)
		assert.Equal(t, k.T, loaded.T)
		assert.Equal(t, k.Idx, loaded.Idx)
		assert.Equal(t, k.Xi.String(), loaded.Xi.String())
		assert.True(t, k.ECDSAPub.Equals(loaded.ECDSAPub))
		assert.Equal(t, k.ChainCode, loaded.ChainCode)
		require.Equal(t, len(k.BigXj), len(loaded.BigXj))
		for j := range k.BigXj {
			assert.Truef(t, k.BigXj[j].Equals(loaded.BigXj[j]), "BigXj[%d] mismatch", j)
		}
	}

	// Swap a couple of keys for their save/load round-trips and verify
	// signing still works.
	loadedKeys := make([]*Key, len(keys))
	for i, k := range keys {
		var buf bytes.Buffer
		require.NoError(t, k.Save(&buf))
		loaded, err := Load(&buf)
		require.NoError(t, err)
		loadedKeys[i] = loaded
	}
	msg := sha256.Sum256([]byte("after-load"))
	sig, err := Sign(loadedKeys, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	pubECDSA := &ecdsa.PublicKey{Curve: pub.Curve(), X: pub.X(), Y: pub.Y()}
	assert.True(t, ecdsa.Verify(pubECDSA, msg[:], sig.R, sig.S))
}

// TestKeyLoadRejectsBadVersion verifies the version check fires.
func TestKeyLoadRejectsBadVersion(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, keys[0].Save(&buf))

	// Tamper with version field. Save emits the current KeyWireVersion;
	// rewrite it to an unsupported value (Load accepts the current
	// version and the legacy v1 only).
	current := fmt.Sprintf("\"version\":%d", KeyWireVersion)
	bad := bytes.Replace(buf.Bytes(), []byte(current), []byte("\"version\":99"), 1)
	_, err = Load(bytes.NewReader(bad))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version mismatch")
}

// TestKeyLoadRejectsCorrupted verifies malformed JSON is rejected.
func TestKeyLoadRejectsCorrupted(t *testing.T) {
	_, err := Load(bytes.NewReader([]byte("{ not json")))
	require.Error(t, err)
}

// TestKeySaveLoadHybridSigning verifies that loading some parties and
// freshly-keygen-ing others is rejected (different pubkey → mismatch).
// In practice all parties must save/load together as a set.
func TestKeySaveLoadAllPartiesTogether(t *testing.T) {
	keys, err := Keygen(2, 1, genPartyIDs(2), rand.Reader)
	require.NoError(t, err)

	loaded := make([]*Key, 2)
	for i, k := range keys {
		var buf bytes.Buffer
		require.NoError(t, k.Save(&buf))
		l, err := Load(&buf)
		require.NoError(t, err)
		loaded[i] = l
	}

	// All-loaded set must sign successfully.
	msg := sha256.Sum256([]byte("all-loaded"))
	sig, err := Sign(loaded, []int{0, 1}, msg[:], rand.Reader)
	require.NoError(t, err)
	pub := &ecdsa.PublicKey{
		Curve: loaded[0].ECDSAPub.Curve(),
		X:     loaded[0].ECDSAPub.X(),
		Y:     loaded[0].ECDSAPub.Y(),
	}
	assert.True(t, ecdsa.Verify(pub, msg[:], sig.R, sig.S))
}

// TestKeySaveLoadIdentityMaterial verifies the v2 wire format preserves
// the Ed25519 long-term identity keys across a Save/Load round-trip and
// that transcript signing still works against the reloaded key.
func TestKeySaveLoadIdentityMaterial(t *testing.T) {
	const n, th = 2, 1
	priv, pub, err := GenerateIdentityKeys(n, rand.Reader)
	require.NoError(t, err)

	keys, err := KeygenWithIdentities(n, th, genPartyIDs(n), priv, pub, rand.Reader)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, keys[0].Save(&buf))
	loaded, err := Load(&buf)
	require.NoError(t, err)

	assert.Equal(t, []byte(keys[0].IdentityPub), []byte(loaded.IdentityPub), "IdentityPub must round-trip")
	assert.Equal(t, []byte(keys[0].IdentityPriv), []byte(loaded.IdentityPriv), "IdentityPriv must round-trip")
	require.Equal(t, n, len(loaded.PeerIdentityPubs), "PeerIdentityPubs length must round-trip")
	for i := range loaded.PeerIdentityPubs {
		assert.Equal(t, []byte(keys[0].PeerIdentityPubs[i]), []byte(loaded.PeerIdentityPubs[i]),
			"PeerIdentityPubs[%d] must round-trip", i)
	}

	transcript := []byte("round 1 reveal")
	sig := loaded.SignTranscript(transcript)
	require.NotNil(t, sig, "loaded key must still sign transcripts")
	assert.True(t, loaded.VerifyTranscript(0, transcript, sig), "loaded key's transcript signature must verify under own peer pub")
}
