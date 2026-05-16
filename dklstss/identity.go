package dklstss

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// GenerateIdentityKeys returns n fresh Ed25519 identity keypairs, one
// per party. Each party should hold its own private key as long-term
// material (e.g., persisted across keygen sessions); the public keys
// are shared across all parties so peers can verify signed transcripts.
//
// Ed25519 is intentionally curve-disjoint from secp256k1: any
// hypothetical bug in the signing-curve primitive doesn't bleed into
// transcript signing.
func GenerateIdentityKeys(n int, rng io.Reader) (priv []ed25519.PrivateKey, pub []ed25519.PublicKey, err error) {
	if rng == nil {
		rng = rand.Reader
	}
	if n <= 0 {
		return nil, nil, errors.New("dklstss: GenerateIdentityKeys n must be > 0")
	}
	priv = make([]ed25519.PrivateKey, n)
	pub = make([]ed25519.PublicKey, n)
	for i := 0; i < n; i++ {
		p, s, err := ed25519.GenerateKey(rng)
		if err != nil {
			return nil, nil, fmt.Errorf("dklstss: GenerateIdentityKeys[%d]: %w", i, err)
		}
		priv[i] = s
		pub[i] = p
	}
	return priv, pub, nil
}

// SignTranscript signs `transcript` with the local identity private key.
// Returns nil if the key has no identity material attached (callers
// using plain Keygen rather than KeygenWithIdentities).
func (k *Key) SignTranscript(transcript []byte) []byte {
	if k == nil || len(k.IdentityPriv) == 0 {
		return nil
	}
	return ed25519.Sign(k.IdentityPriv, transcript)
}

// VerifyTranscript checks that `sig` was produced by the identity
// private key paired with PeerIdentityPubs[partyIdx]. Returns false on
// any failure (out-of-range index, missing public key, invalid signature).
func (k *Key) VerifyTranscript(partyIdx int, transcript, sig []byte) bool {
	if k == nil || partyIdx < 0 || partyIdx >= len(k.PeerIdentityPubs) {
		return false
	}
	pub := k.PeerIdentityPubs[partyIdx]
	if len(pub) == 0 {
		return false
	}
	return ed25519.Verify(pub, transcript, sig)
}

// KeygenWithIdentities runs DKG and attaches the given per-party
// identity keys to each resulting Key. `priv` and `pub` must each have
// length N; `pub` is replicated into every Key.PeerIdentityPubs;
// priv[i] becomes keys[i].IdentityPriv.
//
// In production each party generates its own (priv, pub) pair offline
// and exchanges the public part via a trusted side-channel; this
// function is the in-process equivalent that handles all parties.
func KeygenWithIdentities(n, t int, partyIDs tss.SortedPartyIDs, priv []ed25519.PrivateKey, pub []ed25519.PublicKey, rng io.Reader) ([]*Key, error) {
	if len(priv) != n {
		return nil, fmt.Errorf("dklstss: KeygenWithIdentities priv length %d, expected %d", len(priv), n)
	}
	if len(pub) != n {
		return nil, fmt.Errorf("dklstss: KeygenWithIdentities pub length %d, expected %d", len(pub), n)
	}
	for i := 0; i < n; i++ {
		if priv[i] == nil || pub[i] == nil {
			return nil, fmt.Errorf("dklstss: KeygenWithIdentities entry %d missing identity keys", i)
		}
	}
	keys, err := Keygen(n, t, partyIDs, rng)
	if err != nil {
		return nil, err
	}
	for i, k := range keys {
		k.IdentityPriv = priv[i]
		k.IdentityPub = pub[i]
		k.PeerIdentityPubs = make([]ed25519.PublicKey, n)
		copy(k.PeerIdentityPubs, pub)
	}
	return keys, nil
}
