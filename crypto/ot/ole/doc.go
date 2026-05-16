// Package ole implements ΠMul / Oblivious Linear Evaluation over the
// secp256k1 scalar field on top of crypto/ot/otext.
//
// Functionality: given Alice's input α ∈ F_q and Bob's input β ∈ F_q,
// produces additive shares u_A, u_B ∈ F_q such that u_A + u_B ≡ α·β
// (mod q). The construction is Gilboa-1999 multiplication via random OT:
// Alice's choice bits are the bit-decomposition of α; Bob sends per-row
// correction values (m_0 − m_1 + β·2^i) mod q; Alice combines.
//
// Wire pattern: 2 messages.
//
//	Alice → Bob:  otext.ExtendMsg1 (OT extension with α as choice bits)
//	Bob → Alice:  BobMsg (per-row corrections; ScalarBits entries)
//
// Both parties then compute their share locally.
//
// SECURITY STATUS — PARTIAL.
//
// The construction provided is malicious-secure against Alice (the OT
// extension's consistency check from crypto/ot/otext rejects any per-row
// inconsistency in her choice vector) and SEMI-HONEST against Bob.
//
// A malicious Bob can send arbitrary corrections, causing Alice to
// compute a wrong u_A share — this is a correctness break (later signing
// produces a bad signature) but not a key-extraction attack. DKLs23 §5's
// "Mul-then-check" lifts this to fully malicious by running the protocol
// in parallel under a random Fiat-Shamir tweak and cross-verifying the
// outputs. That upgrade is tracked as task #17 and MUST land before this
// package is wired into signing for production use.
//
// Pre-audit status: unaudited. See crypto/ot/baseot and crypto/ot/otext
// doc comments for the broader security caveat.
//
// References:
//   - J. Doerner, Y. Kondi, E. Lee, A. Shelat. "Threshold ECDSA in Three
//     Rounds", IACR ePrint 2023/765.
//   - N. Gilboa. "Two Party RSA Key Generation", CRYPTO 1999. (Source of
//     the OT-based multiplication construction reused here.)
package ole
