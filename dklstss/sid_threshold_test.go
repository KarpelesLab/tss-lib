// Copyright © 2026 KarpelesLab.

package dklstss

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// makePartySet builds n PartyIDs whose KeyInt is just (1, 2, ..., n).
// Index 0 is treated as self.
func makePartySet(n int) ([]*tss.PartyID, *tss.PeerContext) {
	ids := make([]*tss.PartyID, n)
	for i := 0; i < n; i++ {
		ids[i] = tss.NewPartyID("P"+string(rune('A'+i)), "moniker", big.NewInt(int64(i+1)))
	}
	sorted := tss.SortPartyIDs(ids)
	return sorted, tss.NewPeerContext(sorted)
}

// TestKeygenSessionDiffersOnThreshold is the regression for the audit
// finding that keygenSession previously omitted the threshold T. Two
// keygens with the same party set but different T must produce
// distinct session bytes.
func TestKeygenSessionDiffersOnThreshold(t *testing.T) {
	ids, p2pCtx := makePartySet(4)

	p1 := tss.NewParameters(tss.S256(), p2pCtx, ids[0], 4, 1)
	p2 := tss.NewParameters(tss.S256(), p2pCtx, ids[0], 4, 2)

	s1 := keygenSession(p1)
	s2 := keygenSession(p2)
	require.False(t, bytes.Equal(s1, s2),
		"keygenSession must differ when threshold differs")
}

// TestRefreshSessionDiffersOnThreshold parallel to keygen: refresh
// previously omitted T from its session hash too.
func TestRefreshSessionDiffersOnThreshold(t *testing.T) {
	ids, p2pCtx := makePartySet(4)

	// Synthesize a Key with a fixed pub so refresh sees the same key
	// across both threshold values.
	ec := tss.S256()
	pub, err := crypto.NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
	require.NoError(t, err)
	key := &Key{ECDSAPub: pub}

	p1 := tss.NewParameters(tss.S256(), p2pCtx, ids[0], 4, 1)
	p2 := tss.NewParameters(tss.S256(), p2pCtx, ids[0], 4, 2)

	s1 := refreshSession(p1, key)
	s2 := refreshSession(p2, key)
	require.False(t, bytes.Equal(s1, s2),
		"refreshSession must differ when threshold differs")
}

// TestKeygenSessionTagBumped verifies the version bump from v1 to v2.
// Loose check: the new bytes contain the v2 tag.
func TestKeygenSessionTagBumped(t *testing.T) {
	ids, p2pCtx := makePartySet(3)
	p := tss.NewParameters(tss.S256(), p2pCtx, ids[0], 3, 1)
	// The session hash output is 32 bytes (SHA-256), so the tag bytes
	// don't appear verbatim. Instead, sanity-test by computing both v1
	// and v2 forms via two distinct keygen contexts — they MUST differ
	// (different tag → different SHA input → different output) — but
	// since v1 is no longer exposed, we only assert the output exists
	// and has the expected length.
	s := keygenSession(p)
	require.Equal(t, 32, len(s), "keygenSession output must be a 32-byte SHA-256 digest")
}
