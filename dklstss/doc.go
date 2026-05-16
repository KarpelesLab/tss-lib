// Package dklstss implements threshold ECDSA on secp256k1 following the
// DKLs23 protocol (Doerner, Kondi, Lee, Shelat, "Threshold ECDSA in Three
// Rounds", IACR ePrint 2023/765).
//
// The package wraps crypto/ot/baseot, crypto/ot/otext, and crypto/ot/ole
// to provide:
//   - n-party t-of-n distributed key generation (Feldman VSS based)
//   - t+1-party threshold signing producing standard ECDSA signatures
//   - Pre-signing as a separate offline phase with single-use online sign
//   - Proactive share + OT-extension refresh
//   - Resharing to a new committee (different N, T, members) preserving
//     the public key
//   - HD wallet derivation (BIP32 non-hardened) at sign time
//   - Malicious-secure signing (Mul-then-check) with identifiable abort
//   - Long-term identity keys (Ed25519) for transcript signing
//   - Versioned Key Save/Load for persistence
//
// Compared to the existing GG18-based ecdsatss/ package, dklstss/ has no
// Paillier/MtA layer — the multiplicative-to-additive subprotocol is built
// from oblivious transfer extension instead, sidestepping the entire
// RSA/Paillier-proof attack surface that gave rise to TSSHOCK, Alpha-Rays,
// and related disclosed attacks against GG18 implementations.
//
// APIs: the package provides two styles of every protocol.
//
//   - Synchronous in-process: Keygen, Sign, SignChecked, Presign,
//     SignWithPresign, Refresh, Reshare, DeriveAndSign. Each takes all
//     parties' state as arguments and runs the protocol locally in the
//     caller's goroutine. Intended for tests and direct integration.
//
//   - Broker-driven Party: NewKeygen / NewSigning / NewPresign /
//     NewRefresh / NewResharing each return a per-party state machine
//     that runs over a tss.MessageBroker (mirroring the
//     ecdsatss/eddsatss/frosttss pattern). Round-by-round messages flow
//     via tss.JsonWrap / tss.NewJsonExpect; the result lands on Done
//     or Err. Suited to real distributed deployment (each party in its
//     own process, connected by network transport that implements
//     tss.MessageBroker).
//
// Threading model: a Key produced by Keygen() is read-only after Keygen
// returns. Sign, Presign, SignWithPresign, DeriveChild, DeriveAndSign do
// NOT mutate the Key or its OT-extension setup state; multiple
// goroutines may invoke them concurrently against the same []*Key
// without external synchronization. Refresh DOES return a new []*Key;
// callers must atomically swap the slice reference under their own
// synchronization if they refresh while signing. PresignOutput uses an
// atomic CAS to enforce single-use, so concurrent SignWithPresign
// calls on the same presign are race-safe (exactly one succeeds).
//
// SECURITY STATUS — PRE-AUDIT.
//
// This implementation has NOT received external cryptographic review and
// SHOULD NOT be used in production until that audit completes. The
// protocol surface is feature-complete; what follows is the threat-model
// summary callers should weigh before deployment:
//
//   - Secret-scalar multiplications (signing nonces k_i, base-OT sender
//     trapdoor y) route through crypto/ctmul, which implements a
//     Montgomery ladder over secp256k1 Jacobian coordinates with Z
//     randomization, 64-bit scalar blinding, and byte-level constant-time
//     conditional swap. See ctmul/doc.go for the threat-model details
//     and the residual identity-branch caveat.
//   - ΠMul is malicious-secure against the receiver via the OT extension's
//     KOS-style consistency check, and against the sender via DKLs23 §5
//     "Mul-then-check" (cross-run β-consistency). SignChecked surfaces
//     check failures as tss.Error with Culprits populated; in plain Sign,
//     a malicious party's wrong shares are caught one layer up by ECDSA
//     signature verification.
//   - OT-extension reuse: the long-term OT extension setup established
//     at DKG time is reused across many signing/presigning sessions.
//     The PRG derivation in crypto/ot/otext binds every Extend
//     invocation to its caller-supplied sid, and signing_party.go /
//     presign_party.go mix every signer's freshly-random K_i into the
//     round-2 sid before any ΠMul runs — so re-running the same
//     protocol with identical static inputs (same key, same subset,
//     same message) cannot produce identical OT-extension sids between
//     calls.
//   - Pre-sign single-use is enforced in two layers: an in-memory atomic
//     CAS on PresignOutput, and an optional UsedPresignStore interface
//     for caller-provided durable nonce-commitment tracking across
//     process restarts (SignWithPresignDurable). The library does not
//     prescribe a storage backend — that is the caller's responsibility.
//   - Identifiable abort relies on Ed25519 transcript signatures bound to
//     long-term identity keys established at keygen
//     (KeygenWithIdentities). Without identity keys, blame can still be
//     assigned for cryptographic misbehavior caught by Mul-then-check,
//     but not for transport-level equivocation.
//
// References:
//   - J. Doerner, Y. Kondi, E. Lee, A. Shelat. "Threshold ECDSA in Three
//     Rounds", IACR ePrint 2023/765.
package dklstss
