package otext

// transposeBits transposes a packed-bit matrix.
//
// Input: rows × cols bit matrix stored as `rows` byte slices each of length
// `cols/8` bytes; bit (r, c) is (in[r][c/8] >> (c%8)) & 1.
//
// Output: cols × rows bit matrix stored as `cols` byte slices each of
// length `rows/8` bytes; bit (c, r) of the output equals bit (r, c) of the
// input.
//
// Both `rows` and `cols` must be multiples of 8 and match the input
// dimensions exactly.
//
// This is the straightforward O(rows·cols) loop; a SIMD/SWAR implementation
// is a possible future optimization but the call sites in DKLs23 use modest
// dimensions (rows = κ = 128; cols = a few thousand at most), so this is
// fast enough for now.
func transposeBits(in [][]byte, rows, cols int) [][]byte {
	if rows%8 != 0 {
		panic("otext: transposeBits requires rows divisible by 8")
	}
	if cols%8 != 0 {
		panic("otext: transposeBits requires cols divisible by 8")
	}
	if len(in) != rows {
		panic("otext: transposeBits input row count mismatch")
	}
	colBytes := cols / 8
	for r := 0; r < rows; r++ {
		if len(in[r]) != colBytes {
			panic("otext: transposeBits input column-byte length mismatch")
		}
	}

	rowBytes := rows / 8
	out := make([][]byte, cols)
	for c := 0; c < cols; c++ {
		out[c] = make([]byte, rowBytes)
	}
	for r := 0; r < rows; r++ {
		rowByteIdx := r / 8
		rowBitMask := byte(1) << (uint(r) & 7)
		for cByte := 0; cByte < colBytes; cByte++ {
			b := in[r][cByte]
			if b == 0 {
				continue
			}
			base := cByte * 8
			for cBit := 0; cBit < 8; cBit++ {
				if (b>>uint(cBit))&1 == 1 {
					out[base+cBit][rowByteIdx] |= rowBitMask
				}
			}
		}
	}
	return out
}
