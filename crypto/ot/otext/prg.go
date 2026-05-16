package otext

import (
	"crypto/aes"
	"crypto/cipher"
)

// prgExpand expands a 32-byte seed into n output bytes using AES-128-CTR.
//
// The first 16 bytes of the seed are used as the AES key; the remaining
// 16 bytes become the initial counter (IV). Because base-OT outputs are
// derived from SHA-512/256 over distinct transcripts, the seed's full 32
// bytes are uniformly random and the chance of two seeds colliding in the
// (key, IV) pair is negligible (2^-128 per seed pair).
//
// Output indistinguishability from uniform reduces to the AES-128 PRF
// assumption, which is the standard κ=128-bit-security PRG used by IKNP,
// KOS, and SoftSpokenOT.
func prgExpand(seed [SeedLen]byte, n int) []byte {
	var key [16]byte
	var iv [16]byte
	copy(key[:], seed[0:16])
	copy(iv[:], seed[16:32])

	block, err := aes.NewCipher(key[:])
	if err != nil {
		// aes.NewCipher only fails on key-length mismatch, which cannot
		// happen with a fixed 16-byte slice.
		panic("otext: AES NewCipher unreachable failure: " + err.Error())
	}
	stream := cipher.NewCTR(block, iv[:])
	out := make([]byte, n)
	stream.XORKeyStream(out, out)
	return out
}
