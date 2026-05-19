package eddsatss

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/KarpelesLab/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// randomEd25519Scalar draws a uniform scalar in [1, N-1] for testing.
func randomEd25519Scalar(t *testing.T) *big.Int {
	t.Helper()
	n := tss.Edwards().Params().N
	for {
		buf := make([]byte, 32)
		_, err := rand.Read(buf)
		require.NoError(t, err)
		k := new(big.Int).SetBytes(buf)
		k.Mod(k, n)
		if k.Sign() != 0 {
			return k
		}
	}
}

// TestImportKeyReshareAndSign imports a pre-existing EdDSA private scalar as a
// trivial 1-of-1 share, reshares it into a real t-of-n committee, and verifies
// the new committee can produce signatures that validate under the original
// public key.
func TestImportKeyReshareAndSign(t *testing.T) {
	const (
		newPartyCount = 3
		newThreshold  = 1 // t+1 = 2 signers needed
	)

	// --- PHASE 1: Import an existing Ed25519 key as a 1-of-1 share ---
	priv := randomEd25519Scalar(t)

	oldPIDs := tss.GenerateTestPartyIDs(1)
	require.Len(t, oldPIDs, 1)
	oldPID := oldPIDs[0]

	oldKey, err := ImportKey(priv, oldPID)
	require.NoError(t, err, "ImportKey should succeed on a valid scalar")
	require.NotNil(t, oldKey.EDDSAPub)
	require.Equal(t, priv.Bytes(), oldKey.Xi.Bytes(), "Xi should equal the imported scalar")
	require.Equal(t, oldPID.KeyInt().Bytes(), oldKey.ShareID.Bytes(), "ShareID should be the PartyID KeyInt")
	require.Len(t, oldKey.Ks, 1)
	require.Equal(t, oldPID.KeyInt().Bytes(), oldKey.Ks[0].Bytes(), "Ks[0] should be the PartyID KeyInt")
	require.Len(t, oldKey.BigXj, 1)

	originalPub := oldKey.EDDSAPub

	// --- PHASE 2: Reshare into a new t-of-n committee ---
	oldP2PCtx := tss.NewPeerContext(oldPIDs)
	// Offset new party IDs so their keys can't collide with the single old party's key.
	newPIDsUnsorted := make(tss.UnSortedPartyIDs, 0, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		newPIDsUnsorted = append(newPIDsUnsorted, tss.NewPartyID(
			"new-"+string(rune('A'+i)),
			"new-moniker",
			new(big.Int).SetInt64(int64(1000+i)),
		))
	}
	newPIDs := tss.SortPartyIDs(newPIDsUnsorted)
	newP2PCtx := tss.NewPeerContext(newPIDs)

	rsHub := newResharingHub()
	oldBroker := rsHub.addParty(oldPID)
	newBrokers := make([]*resharingBroker, newPartyCount)
	for i, pid := range newPIDs {
		newBrokers[i] = rsHub.addParty(pid)
	}

	totalParties := 1 + newPartyCount
	resharings := make([]*Resharing, totalParties)

	// Sole old party: oldPartyCount=1, oldThreshold=0.
	oldParams := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, oldPID, 1, 0, newPartyCount, newThreshold)
	oldParams.SetBroker(oldBroker)
	rs, err := NewResharing(context.Background(), oldParams, oldKey)
	require.NoError(t, err, "NewResharing should not fail for the importing old party")
	resharings[0] = rs

	for i := 0; i < newPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, newPIDs[i], 1, 0, newPartyCount, newThreshold)
		params.SetBroker(newBrokers[i])

		rs, err := NewResharing(context.Background(), params, nil)
		require.NoError(t, err, "NewResharing should not fail for new party %d", i)
		resharings[1+i] = rs
	}

	newKeys := make([]*Key, newPartyCount)
	for i := 0; i < totalParties; i++ {
		select {
		case k := <-resharings[i].Done:
			if i == 0 {
				assert.Nil(t, k, "old importing party should emit a nil key (Xi zeroed)")
			} else {
				require.NotNil(t, k, "new party %d should get a key", i-1)
				newKeys[i-1] = k
			}
		case err := <-resharings[i].Err:
			t.Fatalf("Party %d resharing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Party %d resharing timed out", i)
		}
	}

	// Old party's in-memory Xi must have been zeroed by the protocol.
	assert.Equal(t, int64(0), oldKey.Xi.Int64(), "old party Xi must be zeroed after resharing")

	// All new parties must agree on the imported public key.
	for i := 0; i < newPartyCount; i++ {
		require.True(t, originalPub.Equals(newKeys[i].EDDSAPub),
			"new party %d must have the imported EDDSAPub", i)
	}

	// --- PHASE 3: Sign with the new committee ---
	msg := big.NewInt(0xC0FFEE)

	signHub := newTestHub(newPartyCount)
	signings := make([]*Signing, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), newP2PCtx, newPIDs[i], newPartyCount, newThreshold)
		params.SetBroker(signHub.brokers[i])

		sg, err := newKeys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err, "NewSigning should not fail for new party %d", i)
		signings[i] = sg
	}

	sigs := make([]*SignatureData, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		select {
		case sig := <-signings[i].Done:
			sigs[i] = sig
		case err := <-signings[i].Err:
			t.Fatalf("New party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("New party %d signing timed out", i)
		}
	}

	for i := 1; i < newPartyCount; i++ {
		assert.Equal(t, sigs[0].Signature, sigs[i].Signature,
			"new parties 0 and %d should produce the same signature", i)
	}

	// --- PHASE 4: Verify the threshold signature under the imported public key ---
	pk := edwards25519.PublicKey{
		Curve: tss.Edwards(),
		X:     originalPub.X(),
		Y:     originalPub.Y(),
	}
	parsed, err := edwards25519.ParseSignature(sigs[0].Signature)
	require.NoError(t, err, "signature should parse")
	ok := edwards25519.VerifyRS(&pk, msg.Bytes(), parsed.R, parsed.S)
	assert.True(t, ok, "signature from reshared-from-import committee must verify under the imported pub")

	t.Logf("Import + reshare + sign complete. Signature: %x", sigs[0].Signature)
}

// TestImportKeyRejectsInvalidInput covers the defensive checks in ImportKey.
func TestImportKeyRejectsInvalidInput(t *testing.T) {
	pid := tss.GenerateTestPartyIDs(1)[0]

	_, err := ImportKey(nil, pid)
	assert.Error(t, err, "nil priv should error")

	_, err = ImportKey(big.NewInt(0), pid)
	assert.Error(t, err, "zero priv should error")

	// Scalar == N reduces to 0.
	_, err = ImportKey(tss.Edwards().Params().N, pid)
	assert.Error(t, err, "priv == N should error (reduces to 0 mod N)")

	_, err = ImportKey(big.NewInt(1), nil)
	assert.Error(t, err, "nil partyID should error")
}
