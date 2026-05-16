package otext

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
)

// prgExpand expands a 32-byte seed into n output bytes using AES-128-CTR,
// keyed by a per-call derivation that mixes the caller-supplied sid into
// the AES key and IV. The per-call key derivation is critical: without it
// two Extend() invocations against the same ExtReceiver/ExtSender would
// reuse the same (t0, t1) masks and the wire message u = t0⊕t1⊕c would
// leak c¹⊕c² (= bitsLE(α¹)⊕bitsLE(α²)) to the sender across sessions.
//
// Derivation: SHA-512/256("DKLS23-otext-prg-v2" || len(seed)|seed ||
// len(sid)|sid) → 32 bytes; first 16 = AES key, last 16 = AES-CTR IV.
//
// Security: as long as (seed, sid) is distinct across calls, the resulting
// (key, IV) is uniformly random under the SHA-512/256 random-oracle
// assumption, so the AES-CTR stream is computationally independent of
// every other call's stream. AES-128 PRF security gives the standard κ=128
// claim used by IKNP/KOS/SoftSpokenOT.
//
// Backwards-incompatible: the v1 signature (prgExpand(seed, n)) is gone.
// Callers must pass the protocol's session id; the OT-extension layer's
// Extend functions already have a sid in scope, and the consistency-check
// challenge derivation already incorporates the same sid, so binding the
// PRG to it as well costs only one extra SHA-512/256 per Extend.
func prgExpand(seed [SeedLen]byte, sid []byte, n int) []byte {
	h := sha512.New512_256()

	tag := sha512.Sum512_256([]byte("DKLS23-otext-prg-v2"))
	h.Write(tag[:])
	h.Write(tag[:])

	var buf8 [8]byte

	binary.LittleEndian.PutUint64(buf8[:], uint64(len(seed)))
	h.Write(buf8[:])
	h.Write(seed[:])

	binary.LittleEndian.PutUint64(buf8[:], uint64(len(sid)))
	h.Write(buf8[:])
	h.Write(sid)

	derived := h.Sum(nil)
	var key [16]byte
	var iv [16]byte
	copy(key[:], derived[0:16])
	copy(iv[:], derived[16:32])

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
