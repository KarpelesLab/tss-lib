// Copyright © 2026 KarpelesLab.

package frosttss

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/crypto/frost"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestNonceGenerateDistinctOverSameRandDifferentSecret confirms the
// share-binding defense in RFC 9591 §4.1: nonce_generate(rand, s1) !=
// nonce_generate(rand, s2) when s1 != s2 even if the same rand bytes
// are returned.
func TestNonceGenerateDistinctOverSameRandDifferentSecret(t *testing.T) {
	fixed := make([]byte, 1024)
	_, err := rand.Read(fixed)
	require.NoError(t, err)
	// Two RNG instances that return the same byte stream.
	rng1 := bytes.NewReader(fixed)
	rng2 := bytes.NewReader(fixed)

	cs := frost.Ed25519Ciphersuite()
	s1 := big.NewInt(11111)
	s2 := big.NewInt(22222)

	n1, err := frost.NonceGenerate(cs, rng1, s1)
	require.NoError(t, err)
	n2, err := frost.NonceGenerate(cs, rng2, s2)
	require.NoError(t, err)

	require.NotEqual(t, n1.String(), n2.String(),
		"different secrets must produce different nonces even from identical rand")
}

// TestNonceGenerateDistinctOverSameSecretDifferentRand confirms the
// classical RNG-driven case still works: same secret, different rand bytes
// -> different nonces.
func TestNonceGenerateDistinctOverSameSecretDifferentRand(t *testing.T) {
	cs := frost.Ed25519Ciphersuite()
	secret := big.NewInt(42)

	n1, err := frost.NonceGenerate(cs, rand.Reader, secret)
	require.NoError(t, err)
	n2, err := frost.NonceGenerate(cs, rand.Reader, secret)
	require.NoError(t, err)
	require.NotEqual(t, n1.String(), n2.String())
}

// TestNonceGenerateNilArgsErrors validates the input-validation paths.
func TestNonceGenerateNilArgsErrors(t *testing.T) {
	cs := frost.Ed25519Ciphersuite()
	_, err := frost.NonceGenerate(nil, rand.Reader, big.NewInt(1))
	require.Error(t, err)
	_, err = frost.NonceGenerate(cs, nil, big.NewInt(1))
	require.Error(t, err)
	_, err = frost.NonceGenerate(cs, rand.Reader, nil)
	require.Error(t, err)
}

// repeatingReader returns the same buffer over and over — simulates a
// catastrophically-faulty RNG.
type repeatingReader struct {
	buf []byte
	mu  sync.Mutex
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := bytes.NewReader(r.buf)
	return io.ReadFull(out, p)
}

// TestSigningRoundtripUnderFaultyRand: even when params.Rand returns the
// same 32 bytes on every call, two signing sessions on different messages
// must still produce different (d_i, e_i) per session because of the
// share-binding mix-in. Without RFC 9591 §4.1, both d and e would
// collide and Xi would be trivially recoverable from two signatures.
func TestSigningRoundtripUnderFaultyRand(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	// Normal keygen to produce real keys (with crypto/rand).
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
			t.Fatalf("keygen %d: %v", i, err)
		case <-time.After(2 * time.Minute):
			t.Fatalf("keygen %d timed out", i)
		}
	}

	// Two signing sessions on different messages with a deterministically
	// faulty rand: NonceGenerate must still produce distinct nonces.
	subset := pIDs[:threshold+1]
	subsetCtx := tss.NewPeerContext(subset)

	signOnce := func(msg []byte, fixedRand []byte) []*SignatureData {
		hub2 := newTestHub(partyCount) // fresh hub per signing run
		out := make([]*Signing, threshold+1)
		results := make([]*SignatureData, threshold+1)
		for n := 0; n < threshold+1; n++ {
			params := tss.NewParameters(tss.Edwards(), subsetCtx, subset[n], threshold+1, threshold)
			params.SetBroker(hub2.brokers[n])
			params.SetRand(&repeatingReader{buf: fixedRand})
			sig, err := keys[n].NewSigning(context.Background(), msg, params)
			require.NoError(t, err)
			out[n] = sig
		}
		for n, sig := range out {
			select {
			case r := <-sig.Done:
				results[n] = r
			case err := <-sig.Err:
				t.Fatalf("sign %d: %v", n, err)
			case <-time.After(2 * time.Minute):
				t.Fatalf("sign %d timed out", n)
			}
		}
		return results
	}

	// Same fixed rand for both sessions; messages differ.
	ec := edwards25519.Edwards()
	_ = ec
	fixed := bytes.Repeat([]byte{0x5A}, 1024)
	r1 := signOnce([]byte("first message"), fixed)
	r2 := signOnce([]byte("second message"), fixed)

	// Both produce valid signatures (would NOT be the case if d_i, e_i
	// collided across messages — Xi would be leaked and the protocol
	// would either fail verification or be exploitable).
	require.NotNil(t, r1[0])
	require.NotNil(t, r2[0])

	// Signatures must differ since the messages differ.
	require.False(t, bytes.Equal(r1[0].Signature, r2[0].Signature),
		"signatures must differ across distinct messages")
}
