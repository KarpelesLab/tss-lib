// Package mldsatss implements threshold ML-DSA (FIPS 204) signing.
//
// The protocol is the ML-DSA variant from "Threshold Signatures Reloaded:
// ML-DSA and Enhanced Raccoon with Identifiable Aborts" by Borin, Celi,
// del Pino, Espitau, Niot, Prest (ePrint 2025/1166). It produces
// byte-identical FIPS 204 signatures that verify against a stock ML-DSA
// public key.
//
// The current implementation targets ML-DSA-44 and supports any
// (threshold t, parties n) with 2 ≤ t ≤ n ≤ 6. Key generation uses a
// trusted dealer (matching the paper's reference); a distributed key
// generation protocol is not yet defined for this scheme and is left as
// future work.
//
// WARNING: This is an academic-grade prototype. It has NOT received
// independent cryptanalytic review and is NOT suitable for production use.
//
// In particular, the scheme's security rests on the (as-yet unproven in this
// setting) masking argument of ePrint 2025/1166: each party makes a local
// rejection decision and reveals its per-try w_i and z_i, which in principle
// leak information about the secret's norm. Whether the hyperball masking
// fully hides that leakage is a construction- and parameter-level question
// for expert human review. Do not deploy this package, or vary its (t, n)
// parameters, without such review.
package mldsatss
