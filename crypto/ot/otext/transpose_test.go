package otext

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTransposeRoundTrip verifies that transposing twice yields the
// original matrix.
func TestTransposeRoundTrip(t *testing.T) {
	cases := []struct{ rows, cols int }{
		{8, 8},
		{8, 16},
		{16, 8},
		{16, 32},
		{32, 64},
		{128, 256},
	}
	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			rowBytes := tc.cols / 8
			in := make([][]byte, tc.rows)
			for r := range in {
				in[r] = make([]byte, rowBytes)
				_, err := rand.Read(in[r])
				require.NoError(t, err)
			}

			t1 := transposeBits(in, tc.rows, tc.cols)
			t2 := transposeBits(t1, tc.cols, tc.rows)
			require.Len(t, t2, tc.rows)
			for r := 0; r < tc.rows; r++ {
				assert.Equalf(t, in[r], t2[r], "row %d mismatch after round-trip", r)
			}
		})
	}
}

// TestTransposeBitsCorrect verifies bit-level correctness by constructing
// a matrix with a single bit set and asserting the transpose has exactly
// that bit set at the swapped index.
func TestTransposeBitsCorrect(t *testing.T) {
	const rows, cols = 16, 32

	for sr := 0; sr < rows; sr++ {
		for sc := 0; sc < cols; sc++ {
			in := make([][]byte, rows)
			for r := range in {
				in[r] = make([]byte, cols/8)
			}
			in[sr][sc/8] |= 1 << (uint(sc) & 7)

			out := transposeBits(in, rows, cols)
			// Only bit (sc, sr) of output should be set.
			for c := 0; c < cols; c++ {
				for r := 0; r < rows; r++ {
					got := (out[c][r/8] >> (uint(r) & 7)) & 1
					want := byte(0)
					if c == sc && r == sr {
						want = 1
					}
					if got != want {
						t.Fatalf("single-bit (%d,%d) -> transpose bit (%d,%d) got %d want %d",
							sr, sc, c, r, got, want)
					}
				}
			}
		}
	}
}

// TestTransposeFullPattern verifies a sweep across several deterministic
// patterns to catch byte-alignment bugs in the inner loop.
func TestTransposeFullPattern(t *testing.T) {
	const rows, cols = 16, 16
	in := make([][]byte, rows)
	for r := range in {
		in[r] = make([]byte, cols/8)
		// Set bit c iff (r ^ c) is even.
		for c := 0; c < cols; c++ {
			if (r^c)&1 == 0 {
				in[r][c/8] |= 1 << (uint(c) & 7)
			}
		}
	}
	out := transposeBits(in, rows, cols)
	// Check via the inverse property.
	for c := 0; c < cols; c++ {
		for r := 0; r < rows; r++ {
			got := (out[c][r/8] >> (uint(r) & 7)) & 1
			want := byte(0)
			if (r^c)&1 == 0 {
				want = 1
			}
			assert.Equalf(t, want, got, "transpose (c=%d, r=%d)", c, r)
		}
	}
}
