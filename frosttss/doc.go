// Package frosttss is a broker-based implementation of FROST(Ed25519, SHA-512)
// per RFC 9591. It provides keygen, signing, and resharing protocols that
// produce signatures verifiable by any standard Ed25519 verifier.
//
// FROST is a Schnorr-based threshold signature scheme. Compared to the
// GG18-style protocol in eddsatss/, FROST keygen uses a Pedersen DKG (RFC 9591
// Appendix D) and FROST signing uses two preprocessing+signing rounds with a
// binding-factor mechanism that prevents nonce-reuse attacks.
//
// Keys produced by this package are NOT interchangeable with eddsatss.Key.
// Although the on-the-wire Xi value is structurally the same Shamir share, the
// FROST DKG procedure differs from eddsatss keygen (no hash-commitment phase,
// PoK bound only to a_i,0), and signatures use FROST's binding-factor
// aggregation, not the simpler eddsatss aggregation.
//
// # Broker contract
//
// The protocol delegates all transport-layer responsibilities to the
// tss.MessageBroker the caller supplies via params.SetBroker. The broker
// MUST provide the following properties; the protocol's security
// guarantees depend on them:
//
//   - Confidentiality on per-recipient (To != nil) messages. Round-2 DKG
//     shares are encrypted at the application layer (X25519+ChaCha20-
//     Poly1305) so eavesdropping does not break the secret; but the
//     broker may carry signing partial-signature bytes and any other
//     side-channel metadata it observes. Use a TLS or Noise tunnel.
//   - Authenticity on per-sender messages. Peer authentication is OUT OF
//     SCOPE of this package: the broker must pin peer identities and
//     reject spoofed sources. Otherwise a network attacker who can
//     impersonate party j locally is indistinguishable from a corrupted
//     party j.
//   - Reliable, ordered delivery within one keygen / signing / reshare
//     instance.
//   - For To==nil broadcasts: "same bytes to every recipient." The
//     packages do not currently provide an application-layer echo
//     defense for FROST signing, so a malicious broker that ships
//     different bytes to different recipients can DoS the protocol
//     (the joint signature will fail to verify) but cannot extract
//     secrets.
//
// References:
//   - RFC 9591: https://www.rfc-editor.org/rfc/rfc9591.html
//   - FROST paper: https://eprint.iacr.org/2020/852
package frosttss
