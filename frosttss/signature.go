package frosttss

// SignatureData holds the output of a threshold FROST(Ed25519) signing operation.
// Signature is the 64-byte concatenation R || S, identical to a standard
// Ed25519 signature and verifiable by any Ed25519 verifier.
type SignatureData struct {
	R, S      []byte // R is 32-byte canonical Ed25519 encoding of the group commitment; S is 32-byte LE scalar
	Signature []byte // 64-byte signature (R || S)
	M         []byte // original message that was signed
}
