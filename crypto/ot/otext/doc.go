// Package otext implements OT extension on top of crypto/ot/baseot for use
// inside the DKLs23 threshold ECDSA multiplication protocol.
//
// The construction follows the IKNP/KOS lineage with the parameter choice
// k=1, which corresponds to the simplest case of SoftSpokenOT (Roy 2022).
// The small-field k≥2 optimization that gives SoftSpokenOT its name is a
// later milestone; for now, k=1 is sufficient because the protocol-level
// security claims of DKLs23 only require malicious-secure 1-of-2 OT
// extension, regardless of the small-field optimization.
//
// Output: for each session, ExtReceiver supplies L choice bits and learns
// L keys (each KeyLen bytes); ExtSender produces L pairs (m_0, m_1) such
// that the i-th key learned by the receiver equals m_{c_i}[i].
//
// Security: the protocol attaches a KOS-style consistency check —
// σ-dimensional Fiat-Shamir random linear projections of the receiver's
// V and choice vectors, verified by the sender against its Q matrix and
// global Δ. With σ=80 the check rejects any malicious-receiver deviation
// (per-row inconsistency in the choice vector) with probability ≥ 1−2⁻⁸⁰.
//
// Pre-audit status: this package is part of the DKLs23 implementation in
// tss-lib. It has not received external cryptographic review.
//
// Constant-time caveat: inherits the TODO(ConstantTime) issue from
// crypto/ot/baseot. The PRG and matrix transpose in this package are
// data-oblivious; the timing leakage from base-OT scalar multiplication is
// what makes the overall pipeline non-CT today.
//
// References:
//   - L. Roy. "SoftSpokenOT: Quieter OT Extension from Small-Field Silent
//     VOLE in the Minicrypt Model", CRYPTO 2022.
//   - M. Keller, E. Orsini, P. Scholl. "Actively Secure OT Extension with
//     Optimal Overhead", CRYPTO 2015.
//   - Y. Ishai, J. Kilian, K. Nissim, E. Petrank. "Extending Oblivious
//     Transfers Efficiently", CRYPTO 2003.
package otext
