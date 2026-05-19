package frostristretto255tss

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/KarpelesLab/edwards25519"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/group"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestImportKeyHappyPath verifies the basic Key shape.
func TestImportKeyHappyPath(t *testing.T) {
	g := group.Ristretto255()
	q := g.Order()

	priv, err := rand.Int(rand.Reader, q)
	require.NoError(t, err)
	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))

	k, err := ImportKey(priv, importer)
	require.NoError(t, err)
	require.NotNil(t, k)
	require.Equal(t, 0, k.Xi.Cmp(priv))
	require.Equal(t, importer.KeyInt(), k.ShareID)

	want := g.ScalarBaseMult(priv)
	require.True(t, k.GroupPublicKey.Equal(want),
		"GroupPublicKey must equal priv · G on Ristretto255")
}

// TestImportKeyAndReshareRoundTrip imports a Ristretto255 scalar, reshares
// to a real committee, signs with the new committee, and verifies the
// signature under the ORIGINAL pub via VerifySignature.
func TestImportKeyAndReshareRoundTrip(t *testing.T) {
	g := group.Ristretto255()
	q := g.Order()

	priv, err := rand.Int(rand.Reader, q)
	require.NoError(t, err)
	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))

	oldKey, err := ImportKey(priv, importer)
	require.NoError(t, err)
	originalPub := oldKey.GroupPublicKey

	const newN, newT = 5, 2
	// SortPartyIDs assigns the Index field on the importer.
	oldPIDs := tss.SortPartyIDs(tss.UnSortedPartyIDs{importer})
	newPIDs := tss.GenerateTestPartyIDs(newN)
	oldP2P := tss.NewPeerContext(oldPIDs)
	newP2P := tss.NewPeerContext(newPIDs)

	rsHub := newResharingHub()
	oldBroker := rsHub.addParty(importer)
	newBrokers := make([]*resharingBroker, newN)
	for i, pid := range newPIDs {
		newBrokers[i] = rsHub.addParty(pid)
	}

	total := 1 + newN
	resharings := make([]*Resharing, 0, total)

	paramsOld := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P,
		importer, 1, 0, newN, newT)
	paramsOld.SetBroker(oldBroker)
	rsOld, err := NewResharing(context.Background(), paramsOld, oldKey)
	require.NoError(t, err)
	resharings = append(resharings, rsOld)

	for i := 0; i < newN; i++ {
		paramsNew := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P,
			newPIDs[i], 1, 0, newN, newT)
		paramsNew.SetBroker(newBrokers[i])
		rs, err := NewResharing(context.Background(), paramsNew, nil)
		require.NoError(t, err)
		resharings = append(resharings, rs)
	}

	newKeys := make([]*Key, newN)
	for i, rs := range resharings {
		select {
		case k := <-rs.Done:
			if i == 0 {
				require.Nil(t, k, "importer should receive nil key after resharing")
			} else {
				require.NotNil(t, k)
				newKeys[i-1] = k
			}
		case err := <-rs.Err:
			t.Fatalf("resharing error party %d: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("resharing timeout party %d", i)
		}
	}

	for i, k := range newKeys {
		require.Truef(t, originalPub.Equal(k.GroupPublicKey),
			"new party %d GroupPublicKey diverged from imported pub", i)
	}

	// Sign with a T+1 subset.
	signSubset := newPIDs[:newT+1]
	msg := []byte("frostristretto255tss imported-key round trip")
	signHub := newTestHub(newT + 1)
	signings := make([]*Signing, newT+1)
	signCtx := tss.NewPeerContext(signSubset)
	for i := 0; i < newT+1; i++ {
		params := tss.NewParameters(tss.Edwards(), signCtx, signSubset[i], newT+1, newT)
		params.SetBroker(signHub.brokers[i])
		sg, err := newKeys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err)
		signings[i] = sg
	}

	for i, sg := range signings {
		select {
		case result := <-sg.Done:
			require.NotNil(t, result)
			ok, err := VerifySignature(originalPub, msg, result.Signature)
			require.NoError(t, err)
			require.Truef(t, ok, "party %d signature must verify under imported pub", i)
		case err := <-sg.Err:
			t.Fatalf("signing error party %d: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("signing timeout party %d", i)
		}
	}
	_ = edwards25519.Edwards // pin import even if not used directly
}

// TestImportKeyRejectsZeroAndNil covers the input-validation surface.
func TestImportKeyRejectsZeroAndNil(t *testing.T) {
	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))

	_, err := ImportKey(nil, importer)
	require.Error(t, err)

	_, err = ImportKey(big.NewInt(0), importer)
	require.Error(t, err)
	require.Contains(t, err.Error(), "zero")

	_, err = ImportKey(big.NewInt(1), nil)
	require.Error(t, err)
}
