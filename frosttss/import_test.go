package frosttss

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/KarpelesLab/edwards25519"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestImportKeyHappyPath verifies the basic shape: a fresh scalar yields
// a Key whose GroupPublicKey = priv · G with the right one-party
// metadata.
func TestImportKeyHappyPath(t *testing.T) {
	ec := edwards25519.Edwards()
	q := ec.Params().N

	priv, err := rand.Int(rand.Reader, q)
	require.NoError(t, err)
	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))

	k, err := ImportKey(priv, importer)
	require.NoError(t, err)
	require.NotNil(t, k)
	require.Equal(t, priv, k.Xi)
	require.Equal(t, importer.KeyInt(), k.ShareID)
	require.Len(t, k.Ks, 1)
	require.Len(t, k.BigXj, 1)

	want := crypto.CTScalarBaseMultEd25519(ec, priv)
	require.True(t, k.GroupPublicKey.Equals(want),
		"GroupPublicKey must equal priv · G")
	require.True(t, k.BigXj[0].Equals(want),
		"BigXj[0] must equal priv · G for the 1-of-1 case")
}

// TestImportKeyAndReshareRoundTrip is the headline test: take a plain
// Ed25519 scalar, import it as a 1-of-1 frosttss Key, run NewResharing
// to a real t-of-n committee, then sign with the new committee and
// verify the signature under the ORIGINAL pubkey.
func TestImportKeyAndReshareRoundTrip(t *testing.T) {
	ec := edwards25519.Edwards()
	q := ec.Params().N

	priv, err := rand.Int(rand.Reader, q)
	require.NoError(t, err)
	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))

	oldKey, err := ImportKey(priv, importer)
	require.NoError(t, err)
	originalPub := oldKey.GroupPublicKey

	// Resharing from 1-of-1 → t-of-n new committee.
	const newN, newT = 5, 2
	// SortPartyIDs assigns the Index field; without it, PrepareForSigning
	// derefs a -1 index. This matches the convention shown in the
	// ImportKey docs of ecdsatss/eddsatss.
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

	// One importer + N new = total parties for this resharing.
	total := 1 + newN
	resharings := make([]*Resharing, 0, total)

	// Old side: importer.
	paramsOld := tss.NewReSharingParameters(tss.Edwards(), oldP2P, newP2P,
		importer, 1, 0, newN, newT)
	paramsOld.SetBroker(oldBroker)
	rsOld, err := NewResharing(context.Background(), paramsOld, oldKey)
	require.NoError(t, err)
	resharings = append(resharings, rsOld)

	// New side: every new committee party.
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

	// Public key preserved across the new committee.
	for i, k := range newKeys {
		require.Truef(t, originalPub.Equals(k.GroupPublicKey),
			"new party %d: GroupPublicKey diverged from imported pub", i)
	}

	// Sign with the new committee — exact subset of size newThreshold+1.
	signSubset := newPIDs[:newT+1]
	msg := []byte("frosttss imported-key round trip")
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
			// Verify under the ORIGINAL pubkey via edwards25519.VerifyRS
			// (the same primitive the finalize step uses for self-check).
			pk := &edwards25519.PublicKey{
				Curve: ec,
				X:     originalPub.X(),
				Y:     originalPub.Y(),
			}
			rBI := leBytesToBigInt(result.R)
			sBI := leBytesToBigInt(result.S)
			ok := edwards25519.VerifyRS(pk, msg, rBI, sBI)
			require.Truef(t, ok, "party %d signature must verify under imported pubkey", i)
		case err := <-sg.Err:
			t.Fatalf("signing error party %d: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("signing timeout party %d", i)
		}
	}
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

// TestImportKeyReducesPrivModL verifies that priv values outside [0, L)
// are silently reduced to canonical form (matching eddsatss.ImportKey
// behavior).
func TestImportKeyReducesPrivModL(t *testing.T) {
	ec := edwards25519.Edwards()
	q := ec.Params().N

	// priv = q + 1 reduces to 1.
	priv := new(big.Int).Add(q, big.NewInt(1))
	importer := tss.NewPartyID("importer", "importer", big.NewInt(1))

	k, err := ImportKey(priv, importer)
	require.NoError(t, err)
	require.Equal(t, 0, k.Xi.Cmp(big.NewInt(1)),
		"priv mod L should equal 1 for input L+1")
	want := crypto.CTScalarBaseMultEd25519(ec, big.NewInt(1))
	require.True(t, k.GroupPublicKey.Equals(want))
}
