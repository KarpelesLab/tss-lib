package frostristretto255tss

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/stretchr/testify/require"
)

// genKeysForHygiene runs a small keygen and returns the resulting per-party
// Keys, so ValidateBasic / Zeroize can be exercised against real key material.
func genKeysForHygiene(t *testing.T) []*Key {
	t.Helper()
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		keygens[i] = kg
	}
	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
		case err := <-keygens[i].Err:
			t.Fatalf("party %d keygen error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("party %d keygen timed out", i)
		}
	}
	return keys
}

func TestKeyValidateBasicHappyPath(t *testing.T) {
	keys := genKeysForHygiene(t)
	for i, k := range keys {
		require.NoError(t, k.ValidateBasic(), "party %d key should validate", i)
	}
}

func TestKeyValidateBasicNil(t *testing.T) {
	var k *Key
	require.Error(t, k.ValidateBasic())
}

func TestKeyValidateBasicNilXi(t *testing.T) {
	keys := genKeysForHygiene(t)
	k := keys[0]
	k.Xi = nil
	require.Error(t, k.ValidateBasic())
}

func TestKeyValidateBasicIdentityGroupPub(t *testing.T) {
	keys := genKeysForHygiene(t)
	k := keys[0]
	k.GroupPublicKey = group.Ristretto255().Identity()
	require.Error(t, k.ValidateBasic())
}

func TestKeyValidateBasicLengthMismatch(t *testing.T) {
	keys := genKeysForHygiene(t)
	k := keys[0]
	k.BigXj = k.BigXj[:len(k.BigXj)-1]
	require.Error(t, k.ValidateBasic())
}

func TestKeyValidateBasicMismatchedShare(t *testing.T) {
	keys := genKeysForHygiene(t)
	k := keys[0]
	// Perturb Xi so Xi·G no longer equals the public commitment.
	k.Xi = new(big.Int).Add(k.Xi, big.NewInt(1))
	require.Error(t, k.ValidateBasic())
}

func TestKeyZeroizeClearsXi(t *testing.T) {
	keys := genKeysForHygiene(t)
	k := keys[0]
	require.NotZero(t, k.Xi.Sign())
	k.Zeroize()
	require.Equal(t, 0, k.Xi.Sign(), "Xi should be zero after Zeroize")
}

func TestKeyZeroizeNilSafe(t *testing.T) {
	var k *Key
	require.NotPanics(t, func() { k.Zeroize() })
}
