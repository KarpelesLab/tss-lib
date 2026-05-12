package frostristretto255tss

// signRound1msg broadcasts a signer's nonce commitments (D_i, E_i) as 32-byte
// canonical Ristretto255 elements.
type signRound1msg struct {
	Hiding  []byte `json:"hiding"`
	Binding []byte `json:"binding"`
}

// signRound2msg broadcasts the partial signature scalar z_i as 32-byte LE.
type signRound2msg struct {
	Z []byte `json:"z"`
}
