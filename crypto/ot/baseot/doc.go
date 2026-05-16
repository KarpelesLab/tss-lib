// Package baseot implements the Chou-Orlandi "Simplest OT" protocol
// (LATINCRYPT 2015, https://eprint.iacr.org/2015/267) on secp256k1, used as a
// base OT inside the SoftSpokenOT extension layer of the DKLs23 threshold
// ECDSA protocol.
//
// This is a random-OT (ROT) construction: both parties derive their output
// keys from the protocol transcript; no application messages are encrypted.
// The sender attaches a Schnorr proof-of-knowledge of its trapdoor scalar y
// on S = y·G, which is required for UC-malicious security against a
// malicious sender. The receiver is malicious-secure by construction
// (R = x·G + c·S is uniform in the group regardless of c).
//
// Pre-audit status: this package is part of the DKLs23 implementation in
// tss-lib. It has not received external cryptographic review. Do not use in
// production until audited.
//
// Constant-time properties: the sender's secret trapdoor y appears in
// three scalar multiplications (S = y·G, yS = y·S, yR_i = y·R_i for each
// OT instance). All three route through crypto/ctmul, which implements
// a Montgomery ladder over secp256k1 Jacobian coordinates with Z
// randomization, 64-bit scalar blinding, and byte-level constant-time
// conditional swap. The receiver's per-OT randomness x_i is computed via
// the standard (non-CT) ScalarBaseMult; this is a deliberate choice —
// x_i is per-OT-fresh-per-receiver randomness, not a long-term secret,
// and learning x_i lets the sender compute keys it already knows.
package baseot
