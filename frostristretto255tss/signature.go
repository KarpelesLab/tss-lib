package frostristretto255tss

// SignatureData holds the output of a threshold FROST(ristretto255) signing
// operation. Signature is the 64-byte concatenation R || S where R is the
// 32-byte canonical Ristretto255 encoding of the group commitment and S is
// the 32-byte little-endian scalar.
//
// This signature format is NOT interchangeable with Ed25519. Verifiers must
// be Ristretto255-aware (re-derive the challenge as
// H2(R || pubkey || msg) under the FROST-RISTRETTO255-SHA512-v1 ciphersuite).
type SignatureData struct {
	R, S      []byte
	Signature []byte
	M         []byte
}
