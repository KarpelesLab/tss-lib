// Copyright © 2026 KarpelesLab.

package frosttss

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestKeyValidateBasicHappyPath: a freshly keygen'd Key passes
// ValidateBasic.
func TestKeyValidateBasicHappyPath(t *testing.T) {
	const partyCount, threshold = 3, 1
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
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			require.NoError(t, k.ValidateBasic(), "party %d ValidateBasic must pass", i)
		case e := <-keygens[i].Err:
			t.Fatalf("party %d keygen: %v", i, e)
		case <-time.After(2 * time.Minute):
			t.Fatalf("party %d keygen timed out", i)
		}
	}
}

// TestKeyValidateBasicNil rejects nil receiver.
func TestKeyValidateBasicNil(t *testing.T) {
	var k *Key
	require.Error(t, k.ValidateBasic())
}

// TestKeyValidateBasicNilXi: nil Xi → error.
func TestKeyValidateBasicNilXi(t *testing.T) {
	k := &Key{
		ShareID:        big.NewInt(1),
		Ks:             []*big.Int{big.NewInt(1)},
		BigXj:          []*crypto.ECPoint{crypto.CTScalarBaseMultEd25519(frost.EdwardsCurve(), big.NewInt(1))},
		GroupPublicKey: crypto.CTScalarBaseMultEd25519(frost.EdwardsCurve(), big.NewInt(1)),
	}
	err := k.ValidateBasic()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Xi is nil")
}

// TestKeyValidateBasicMismatchedShare: Xi · G != BigXj[i] → error.
func TestKeyValidateBasicMismatchedShare(t *testing.T) {
	ec := frost.EdwardsCurve()
	// Xi = 7, but BigXj[0] is set to the base point G (= 1·G). Mismatch.
	k := &Key{
		Xi:             big.NewInt(7),
		ShareID:        big.NewInt(1),
		Ks:             []*big.Int{big.NewInt(1)},
		BigXj:          []*crypto.ECPoint{crypto.CTScalarBaseMultEd25519(ec, big.NewInt(1))},
		GroupPublicKey: crypto.CTScalarBaseMultEd25519(ec, big.NewInt(7)),
	}
	err := k.ValidateBasic()
	require.Error(t, err)
	require.Contains(t, err.Error(), "binding broken")
}

// TestKeyValidateBasicIdentityGroupPub: GroupPublicKey == identity → error.
func TestKeyValidateBasicIdentityGroupPub(t *testing.T) {
	ec := frost.EdwardsCurve()
	identity, err := crypto.NewECPoint(ec, big.NewInt(0), big.NewInt(1))
	require.NoError(t, err)
	k := &Key{
		Xi:             big.NewInt(1),
		ShareID:        big.NewInt(1),
		Ks:             []*big.Int{big.NewInt(1)},
		BigXj:          []*crypto.ECPoint{crypto.CTScalarBaseMultEd25519(ec, big.NewInt(1))},
		GroupPublicKey: identity,
	}
	err = k.ValidateBasic()
	require.Error(t, err)
	require.Contains(t, err.Error(), "identity")
}

// TestKeyValidateBasicLengthMismatch: len(Ks) != len(BigXj) → error.
func TestKeyValidateBasicLengthMismatch(t *testing.T) {
	ec := frost.EdwardsCurve()
	k := &Key{
		Xi:             big.NewInt(1),
		ShareID:        big.NewInt(1),
		Ks:             []*big.Int{big.NewInt(1), big.NewInt(2)},
		BigXj:          []*crypto.ECPoint{crypto.CTScalarBaseMultEd25519(ec, big.NewInt(1))},
		GroupPublicKey: crypto.CTScalarBaseMultEd25519(ec, big.NewInt(1)),
	}
	err := k.ValidateBasic()
	require.Error(t, err)
	require.Contains(t, err.Error(), "length")
}

// TestKeyValidateBasicShareIDNotInKs: ShareID not in Ks → error.
func TestKeyValidateBasicShareIDNotInKs(t *testing.T) {
	ec := frost.EdwardsCurve()
	k := &Key{
		Xi:             big.NewInt(1),
		ShareID:        big.NewInt(99),
		Ks:             []*big.Int{big.NewInt(1), big.NewInt(2)},
		BigXj:          []*crypto.ECPoint{crypto.CTScalarBaseMultEd25519(ec, big.NewInt(1)), crypto.CTScalarBaseMultEd25519(ec, big.NewInt(2))},
		GroupPublicKey: crypto.CTScalarBaseMultEd25519(ec, big.NewInt(3)),
	}
	err := k.ValidateBasic()
	require.Error(t, err)
	require.Contains(t, err.Error(), "ShareID not found")
}
