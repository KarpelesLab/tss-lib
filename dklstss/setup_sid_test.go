package dklstss

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEncodePartyPairInjective verifies that (i, j, dir) maps to distinct
// byte strings for distinct triples, including the boundary case where the
// previous byte() truncation would have collided ((0,1) vs (256,257)).
func TestEncodePartyPairInjective(t *testing.T) {
	cases := []struct {
		i, j int
		dir  byte
	}{
		{0, 1, 'A'},
		{0, 1, 'B'},
		{1, 0, 'A'},
		{1, 0, 'B'},
		{256, 257, 'A'},
		{256, 257, 'B'},
		{0xFFFFFFFE, 0xFFFFFFFF, 'A'},
	}
	seen := make(map[string]struct{})
	for _, c := range cases {
		b := encodePartyPair(c.i, c.j, c.dir)
		require.Len(t, b, 9)
		k := string(b)
		_, dup := seen[k]
		require.Falsef(t, dup, "duplicate encoding for (%d, %d, %c)", c.i, c.j, c.dir)
		seen[k] = struct{}{}
	}

	// Specifically: (0, 1, A) must NOT equal (256, 257, A). Under the old
	// byte() truncation form they had identical sid suffix bytes.
	a := encodePartyPair(0, 1, 'A')
	b := encodePartyPair(256, 257, 'A')
	require.False(t, bytes.Equal(a, b), "n>256 sids must not collide with n<256 sids")
}

// TestEncodePartyPairDirSeparation verifies dir A and dir B produce
// distinct encodings for the same (i, j) — the OT-pair has two
// directions and a sid collision between them would mix the receiver
// and sender state.
func TestEncodePartyPairDirSeparation(t *testing.T) {
	a := encodePartyPair(7, 11, 'A')
	b := encodePartyPair(7, 11, 'B')
	require.False(t, bytes.Equal(a, b), "direction byte must differentiate sids")
}
