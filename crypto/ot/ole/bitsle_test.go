package ole

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBitsLECorrectness verifies that bitsLE encodes v as little-endian
// 32-byte choice bits where bit i is (out[i/8] >> (i%8)) & 1 == v.Bit(i).
//
// The test sweeps a mix of edge values (0, 1, 2^255, q-1) plus random
// scalars to catch off-by-one and bit-order bugs in the unconditional-OR
// rewrite.
func TestBitsLECorrectness(t *testing.T) {
	q, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	require.True(t, ok)
	pat, ok := new(big.Int).SetString("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 16)
	require.True(t, ok)

	cases := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Lsh(big.NewInt(1), 255),
		new(big.Int).Sub(q, big.NewInt(1)),
		pat,
	}
	for i := 0; i < 16; i++ {
		r, err := rand.Int(rand.Reader, q)
		require.NoError(t, err)
		cases = append(cases, r)
	}

	for _, v := range cases {
		out := bitsLE(v)
		require.Len(t, out, 32)
		for i := 0; i < ScalarBits; i++ {
			expected := byte(v.Bit(i))
			got := (out[i/8] >> (uint(i) & 7)) & 1
			require.Equalf(t, expected, got,
				"bit %d mismatch for v=%s (got=%d want=%d)",
				i, v.Text(16), got, expected)
		}
	}
}

// TestBitsLEAllZero is a regression test for the unconditional-OR rewrite:
// the function must produce an all-zero output for v=0, and the result is
// computed via the same code path as any other v (no fast-path).
func TestBitsLEAllZero(t *testing.T) {
	out := bitsLE(big.NewInt(0))
	require.Len(t, out, 32)
	for i, b := range out {
		require.Zerof(t, b, "byte %d of bitsLE(0) must be 0", i)
	}
}

// TestBitsLEAllOne is the complementary regression test: every bit set
// for the value 2^256 - 1 (truncation drops bits ≥ 256, so we use
// 2^256 - 1).
func TestBitsLEAllOne(t *testing.T) {
	v := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	out := bitsLE(v)
	require.Len(t, out, 32)
	for i, b := range out {
		require.Equalf(t, byte(0xFF), b, "byte %d of bitsLE(2^256-1) must be 0xFF", i)
	}
}
