// Package dklstss implements threshold ECDSA on secp256k1 following the
// DKLs23 protocol (Doerner, Kondi, Lee, Shelat, "Threshold ECDSA in Three
// Rounds", IACR ePrint 2023/765).
//
// The package wraps crypto/ot/baseot, crypto/ot/otext, and crypto/ot/ole
// to provide:
//   - n-party t-of-n distributed key generation (Feldman VSS based)
//   - t+1-party threshold signing producing standard ECDSA signatures
//   - HD wallet derivation (BIP32 non-hardened) at sign time
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
// SECURITY STATUS — PRE-AUDIT and PARTIAL.
//
// This implementation has NOT received external cryptographic review and
// SHOULD NOT be used in production. Several known gaps remain (each
// tracked in the project task list):
//
//   - Secret-scalar multiplications (signing nonces k_i, base-OT sender
//     trapdoor y) route through crypto/ctmul, which implements a
//     Montgomery ladder over secp256k1 Jacobian coordinates with Z
//     randomization, 64-bit scalar blinding, and byte-level constant-time
//     conditional swap. See ctmul/doc.go for the threat-model details
//     and the residual identity-branch caveat.
//   - ΠMul provides malicious-receiver security via the OT extension's
//     consistency check, but malicious-sender security (DKLs23 §5's
//     "Mul-then-check") is task #17. A malicious Bob can today cause Alice
//     to compute wrong shares (correctness break / DoS, not key
//     extraction).
//   - Pre-signing as a separate offline phase is task #12. The current
//     API offers only combined (online) signing.
//   - Proactive share refresh is task #13.
//   - Broker-based async API matching ecdsatss/ is task #7. Today's API
//     is synchronous and intended for tests and direct integration. The
//     wire-message Go structs are defined in msgkeygen.go, msgsigning.go,
//     and msgrefresh.go for the future broker-driven Party state machine
//     to use via tss.JsonWrap / tss.NewJsonExpect, matching the existing
//     convention used by ecdsatss/eddsatss/frosttss.
//
// References:
//   - J. Doerner, Y. Kondi, E. Lee, A. Shelat. "Threshold ECDSA in Three
//     Rounds", IACR ePrint 2023/765.
package dklstss
