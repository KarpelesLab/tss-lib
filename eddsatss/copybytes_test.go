package eddsatss

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCopyBytesShortInput verifies that short inputs are correctly
// left-padded with zeros — i.e. the value lives in the high bytes of a
// big-endian representation.
func TestCopyBytesShortInput(t *testing.T) {
	cases := map[int][]byte{
		1:  {0xAA},
		16: bytes.Repeat([]byte{0x5A}, 16),
		31: bytes.Repeat([]byte{0xC3}, 31),
	}
	for size, in := range cases {
		out := copyBytes(in)
		require.Equal(t, 32, len(out))
		// Leading 32-size bytes should be zero.
		for i := 0; i < 32-size; i++ {
			require.Zerof(t, out[i], "size=%d byte %d should be zero", size, i)
		}
		// Trailing bytes should equal the input.
		require.Equalf(t, in, out[32-size:],
			"size=%d trailing bytes should equal input", size)
	}
}

// TestCopyBytesExact32 verifies the identity case.
func TestCopyBytesExact32(t *testing.T) {
	in := make([]byte, 32)
	_, err := rand.Read(in)
	require.NoError(t, err)
	out := copyBytes(in)
	require.Equal(t, in, out[:])
}

// TestCopyBytesNil returns nil for nil input (existing contract).
func TestCopyBytesNil(t *testing.T) {
	require.Nil(t, copyBytes(nil))
}

// TestCopyBytesLongInputTakesLowBytes verifies the regression fix: an
// input longer than 32 bytes returns the LOW 32 bytes of the big-endian
// representation, not the high 32. The previous implementation took the
// high bytes, which for `new(big.Int).SetBytes(...)` consumers meant the
// LOW bits of a multi-precision value were silently dropped.
func TestCopyBytesLongInputTakesLowBytes(t *testing.T) {
	// Build a 64-byte big-endian value where the top 32 bytes are 0xAA
	// and the bottom 32 are 0x55 — distinct so we can tell which side
	// survives.
	in := make([]byte, 64)
	for i := 0; i < 32; i++ {
		in[i] = 0xAA
		in[32+i] = 0x55
	}
	out := copyBytes(in)
	// Expected: the bottom 32 bytes (all 0x55).
	for i := 0; i < 32; i++ {
		require.Equalf(t, byte(0x55), out[i],
			"byte %d should be 0x55 (low half), got 0x%02X", i, out[i])
	}
}

// TestCopyBytesEquivalentToMod2Pow256 verifies the semantic guarantee:
// copyBytes(x.Bytes()) on x > 2^256 must equal copyBytes((x mod 2^256).Bytes()).
func TestCopyBytesEquivalentToMod2Pow256(t *testing.T) {
	// Random 64-byte big-endian = value < 2^512.
	raw := make([]byte, 64)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	x := new(big.Int).SetBytes(raw)

	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	reduced := new(big.Int).Mod(x, mod)

	gotRaw := copyBytes(x.Bytes())
	gotReduced := copyBytes(reduced.Bytes())

	require.Equal(t, gotReduced[:], gotRaw[:],
		"copyBytes should equal copyBytes(value mod 2^256)")
}
