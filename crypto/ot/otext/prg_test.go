package otext

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPRGDeterministic verifies that prgExpand is deterministic on the same
// (seed, sid, length) and produces independent-looking outputs for
// different seeds.
func TestPRGDeterministic(t *testing.T) {
	var seedA, seedB [SeedLen]byte
	for i := range seedA {
		seedA[i] = byte(i)
	}
	for i := range seedB {
		seedB[i] = byte(i + 1)
	}
	sid := []byte("test-sid")

	outA1 := prgExpand(seedA, sid, 256)
	outA2 := prgExpand(seedA, sid, 256)
	outB := prgExpand(seedB, sid, 256)

	assert.Equal(t, outA1, outA2, "same (seed,sid) must give same PRG output")
	assert.NotEqual(t, outA1, outB, "different seeds must give different PRG outputs")
	assert.Len(t, outA1, 256)
}

// TestPRGSidBinding verifies that the PRG output changes when the sid
// changes — this is the property that prevents OT-extension seed reuse
// across multiple Extend invocations from leaking choice bits.
func TestPRGSidBinding(t *testing.T) {
	var seed [SeedLen]byte
	for i := range seed {
		seed[i] = byte(i + 3)
	}

	outA := prgExpand(seed, []byte("sid-A"), 256)
	outB := prgExpand(seed, []byte("sid-B"), 256)

	assert.NotEqual(t, outA, outB, "different sids on the same seed must produce different outputs")
}

// TestPRGLengthAgreement checks that asking for L bytes returns L bytes,
// and that shorter and longer requests on the same (seed, sid) are
// consistent prefixes (AES-CTR property — the first n bytes of an N-byte
// expansion equal an n-byte expansion).
func TestPRGLengthAgreement(t *testing.T) {
	var seed [SeedLen]byte
	for i := range seed {
		seed[i] = byte(i ^ 0xAA)
	}
	sid := []byte("test-sid")

	short := prgExpand(seed, sid, 64)
	long := prgExpand(seed, sid, 256)

	assert.Len(t, short, 64)
	assert.Len(t, long, 256)
	assert.True(t, bytes.Equal(short, long[:64]), "prgExpand must be a prefix function: short output should be a prefix of longer output")
}

// TestPRGNonzero is a smoke test that the PRG output looks reasonably
// non-trivial (not all zero bytes, not all same byte).
func TestPRGNonzero(t *testing.T) {
	var seed [SeedLen]byte
	for i := range seed {
		seed[i] = byte(i + 17)
	}

	out := prgExpand(seed, []byte("sid"), 1024)
	allZero := true
	allSame := true
	first := out[0]
	for _, b := range out {
		if b != 0 {
			allZero = false
		}
		if b != first {
			allSame = false
		}
	}
	assert.False(t, allZero, "PRG output should not be all zero")
	assert.False(t, allSame, "PRG output should not be constant")
}
