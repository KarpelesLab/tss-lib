# Multi-Party Threshold Signature Scheme
[![MIT licensed][1]][2] [![GoDoc][3]][4] [![Go Report Card][5]][6] [![Coverage Status][7]][8]

[1]: https://img.shields.io/badge/license-MIT-blue.svg
[2]: LICENSE
[3]: https://godoc.org/github.com/KarpelesLab/tss-lib/v2?status.svg
[4]: https://godoc.org/github.com/KarpelesLab/tss-lib/v2
[5]: https://goreportcard.com/badge/github.com/KarpelesLab/tss-lib
[6]: https://goreportcard.com/report/github.com/KarpelesLab/tss-lib
[7]: https://coveralls.io/repos/github/KarpelesLab/tss-lib/badge.svg?branch=master
[8]: https://coveralls.io/github/KarpelesLab/tss-lib?branch=master

Permissively MIT Licensed.

## Introduction
This is an implementation of multi-party {t,n}-threshold ECDSA (Elliptic Curve Digital Signature Algorithm) based on Gennaro and Goldfeder CCS 2018 [1] and EdDSA (Edwards-curve Digital Signature Algorithm) following a similar approach.

This library includes three protocols:

* Key Generation for creating secret shares with no trusted dealer ("keygen").
* Signing for using the secret shares to generate a signature ("signing").
* Dynamic Groups to change the group of participants while keeping the secret ("resharing").

It also ships an **experimental** post-quantum threshold signer in the `mldsatss` package, implementing the ML-DSA-44 (FIPS 204) variant of "Threshold Signatures Reloaded" [2]. The output signatures are byte-identical to stock FIPS 204 and verify with any standard ML-DSA verifier.

⚠️ Do not miss [these important notes](#how-to-use-this-securely) on implementing this library securely

## Rationale
ECDSA is used extensively for crypto-currencies such as Bitcoin, Ethereum (secp256k1 curve), NEO (NIST P-256 curve) and many more. 

EdDSA is used extensively for crypto-currencies such as Cardano, Aeternity, Stellar Lumens and many more.

For such currencies this technique may be used to create crypto wallets where multiple parties must collaborate to sign transactions. See [MultiSig Use Cases](https://en.bitcoin.it/wiki/Multisignature#Multisignature_Applications)

One secret share per key/address is stored locally by each participant and these are kept safe by the protocol – they are never revealed to others at any time. Moreover, there is no trusted dealer of the shares.

In contrast to MultiSig solutions, transactions produced by TSS preserve the privacy of the signers by not revealing which `t+1` participants were involved in their signing.

There is also a performance bonus in that blockchain nodes may check the validity of a signature without any extra MultiSig logic or processing.

## Usage (v2.2+ — Recommended)

The `ecdsatss` and `eddsatss` packages provide a broker-based API that is simpler to use than the legacy channel-based API. Messages are routed automatically through a `tss.MessageBroker`, and protocol rounds chain via callbacks — no manual channel management or message routing required.

### Setup
```go
// Create PartyIDs for each participant
parties := tss.SortPartyIDs(getParticipantPartyIDs())
ctx := tss.NewPeerContext(parties)
thisParty := tss.NewPartyID(id, moniker, uniqueKey)

// Select a curve: tss.S256() for ECDSA, tss.Edwards() for EdDSA
params := tss.NewParameters(tss.S256(), ctx, thisParty, len(parties), threshold)

// Set a MessageBroker that routes messages between parties over your transport
params.SetBroker(myBroker)
```

The broker must implement `tss.MessageBroker`:
- `Receive(msg *tss.JsonMessage) error` — called by the protocol to send outgoing messages; your implementation should route them to the destination party's broker.
- `Connect(typ string, dest tss.MessageReceiver)` — called by the protocol to register handlers for incoming messages by type.

### ECDSA Keygen
```go
// Pre-compute Paillier key and safe primes (recommended out-of-band)
preParams, _ := ecdsatss.GeneratePreParams(5 * time.Minute)

kg, err := ecdsatss.NewKeygen(ctx, params, *preParams)
// Wait for result:
select {
case key := <-kg.Done:
    // Persist key to secure storage
case err := <-kg.Err:
    // Handle error
}
```

### ECDSA Signing
```go
sig, err := key.NewSigning(ctx, msgHash, params)
select {
case result := <-sig.Done:
    // result.Signature contains R || S
    // result.Recovery contains the recovery byte
case err := <-sig.Err:
    // Handle error
}
```

### ECDSA Re-Sharing
```go
// Old committee members pass their key; new committee members pass nil
rs, err := ecdsatss.NewResharing(ctx, resharingParams, oldKey, *newPreParams)
select {
case newKey := <-rs.Done:
    // New committee: persist newKey
    // Old committee: receives nil (old key is zeroed)
case err := <-rs.Err:
    // Handle error
}
```

### EdDSA

The `eddsatss` package follows the same pattern but is simpler (no Paillier keys or pre-params):

```go
// Keygen
kg, err := eddsatss.NewKeygen(ctx, params)
key := <-kg.Done

// Signing
sig, err := key.NewSigning(ctx, msg, params)
result := <-sig.Done // result.Signature is 64-byte Ed25519 signature

// Re-sharing
rs, err := eddsatss.NewResharing(ctx, resharingParams, oldKey)
newKey := <-rs.Done
```

### FROST (Ed25519)

The `frosttss` package implements FROST (Flexible Round-Optimized Schnorr Threshold) over Ed25519 per [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) §6.1. It is Schnorr-based, uses a Pedersen DKG (RFC 9591 Appendix D), and produces 64-byte signatures verifiable by any standard Ed25519 verifier.

Compared to `eddsatss`, FROST signing is leaner (two rounds vs three) and uses the FROST binding-factor aggregation that prevents nonce-reuse attacks. Keys produced by `frosttss` are NOT interchangeable with `eddsatss` keys — the DKG, the per-party-state shape, and the aggregation logic all differ.

```go
import "github.com/KarpelesLab/tss-lib/v2/frosttss"

// Keygen — Pedersen DKG; no pre-params required
kg, err := frosttss.NewKeygen(ctx, params)
key := <-kg.Done // key.GroupPublicKey is the Ed25519 public key

// Signing — RFC 9591 two-round non-coordinator protocol
sig, err := key.NewSigning(ctx, msg, params)
result := <-sig.Done // result.Signature is a 64-byte Ed25519 signature

// Re-sharing
rs, err := frosttss.NewResharing(ctx, resharingParams, oldKey)
newKey := <-rs.Done
```

### FROST (Ristretto255)

The `frostristretto255tss` package implements FROST(ristretto255, SHA-512) per [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) §6.2. The protocol shape is identical to `frosttss`, but signatures are 64 bytes in the natural Ristretto255 format (32-byte R || 32-byte S) and are **not** Ed25519-compatible — verifiers must be Ristretto-aware.

```go
import "github.com/KarpelesLab/tss-lib/v2/frostristretto255tss"

// Keygen
kg, err := frostristretto255tss.NewKeygen(ctx, params)
key := <-kg.Done // key.GroupPublicKey is a *crypto/group.Element (Ristretto255)

// Signing
sig, err := key.NewSigning(ctx, msg, params)
result := <-sig.Done

// Verify externally
ok, err := frostristretto255tss.VerifySignature(key.GroupPublicKey, msg, result.Signature)
```

Both FROST packages share `crypto/frost` (ciphersuite + binding) and `crypto/group` (the prime-order group abstraction shared by Ed25519 and Ristretto255). Construct `tss.Parameters` with `tss.Edwards()` as a placeholder curve when calling the Ristretto255 package — the Ed25519 elliptic curve is unused, but its scalar field matches Ristretto255's so the parameters are otherwise compatible.

A FROST-style threshold ECDSA path (Lindell-Tseng / GG24 hybrid with a separate aux-info round) is planned as a follow-up phase.

### Importing an existing key

Both `ecdsatss` and `eddsatss` provide an `ImportKey` helper that wraps a plain,
non-TSS private key as a trivial 1-of-1 share. The resulting `*Key` can be fed
into `NewResharing` as the sole old-committee input, so an existing key can be
split into a real t-of-n threshold committee without regenerating the public
key.

⚠️ **This defeats one of TSS's core properties.** A correct DKG guarantees that
the full private key never exists on any single machine. `ImportKey` violates
that by construction — at the moment of import, one party holds the entire
scalar. Only use it to migrate a pre-existing (legacy, single-signer) key into
a threshold setup; for brand-new keys, use `NewKeygen` instead.

```go
// ECDSA: priv is a *ecdsa.PrivateKey you already hold.
importer := tss.NewPartyID("importer", "importer", uniqueKey)
oldKey, err := ecdsatss.ImportKey(priv, importer)

// Run resharing from a 1-of-1 "old committee" into a real t-of-n "new committee".
oldCtx := tss.NewPeerContext(tss.SortPartyIDs(tss.UnSortedPartyIDs{importer}))
newCtx := tss.NewPeerContext(newParties)
params := tss.NewReSharingParameters(
    tss.S256(), oldCtx, newCtx, importer,
    /*oldPartyCount*/ 1, /*oldThreshold*/ 0,
    /*newPartyCount*/ n, /*newThreshold*/ t,
)
rs, err := ecdsatss.NewResharing(ctx, params, oldKey)
// The importer's <-rs.Done delivers a key with Xi zeroed; each new party
// receives its share. All new shares verify under priv.PublicKey.
```

`eddsatss.ImportKey(priv *big.Int, partyID *tss.PartyID)` works the same way
for Ed25519 scalars on `tss.Edwards()`.

### Post-Quantum Threshold ML-DSA (experimental)

The `mldsatss` package implements the ML-DSA-44 variant of "Threshold Signatures Reloaded" [2]. The protocol is a 3-round exchange (commit hash → reveal w → responses) with a reject-and-retry outer loop; the final output is a standard FIPS 204 signature.

⚠️ **Research-grade prototype.** The scheme is not standardized and has not received independent cryptanalytic review, so it is **not** suitable for production. Track NIST IR 8214C for standardization progress before deploying anything based on this package.

Current scope:
- ML-DSA-44 only (ML-DSA-65 / ML-DSA-87 not yet plumbed).
- **Trusted-dealer** keygen from a 32-byte seed, matching the paper's reference. No DKG yet — distributed key generation for this scheme is an open research question.
- Signing committees with `2 ≤ t ≤ n ≤ 6`. The paper's hardcoded parameter table (K, r, r′, ν) and honest-signer sharing patterns are copied verbatim into [`mldsatss/params.go`](mldsatss/params.go).
- No resharing, no identifiable aborts.

Trusted-dealer keygen:

```go
import "github.com/KarpelesLab/tss-lib/v2/mldsatss"

// Threshold parameters for (t, n).
tParams, err := mldsatss.GetThresholdParams44(t, n)

// Trusted dealer derives pk and N per-party Keys deterministically from seed.
pk, keys, err := mldsatss.TrustedDealerKeygen44(seed, tParams)
```

Signing (per party). Each signer constructs its own `mldsatss.Signing44`; messages are routed through the same `tss.MessageBroker` abstraction as ecdsatss/eddsatss:

```go
// Build a sorted committee of T signers and the list of their Key44.Id values
// in that sorted order, then wire a broker for each party.
p2pCtx := tss.NewPeerContext(signers)
params, err := mldsatss.NewParameters(myPartyID, p2pCtx, tParams, keyIds, broker)

// Kick off one 3-round attempt.
s, err := mldsatss.NewSigning44(ctx, params, myKey, msg, msgCtx)
select {
case result := <-s.Done:
    // result.Signature is a standard FIPS 204 ML-DSA-44 signature.
case err := <-s.Err:
    // ErrAllTriesRejected: every try in this 3-round exchange failed the
    // rejection bound. Retry with params.SetAttemptID(nextID) and a fresh
    // Signing44 until one succeeds. For (t=2, n=2) with K=2, expect a
    // handful of retries on average; for larger (t, n) the paper tunes K
    // so that typical success is 1–3 attempts.
}
```

After success, `pk.Verify(result.Signature, msg, msgCtx)` (on the same `*mldsa.PublicKey44` returned by the trusted dealer) will return true.

## Migration from Legacy API (v2.1 and earlier)

The `ecdsa/keygen`, `ecdsa/signing`, `ecdsa/resharing`, `eddsa/keygen`, `eddsa/signing`, and `eddsa/resharing` packages are now **deprecated**. They still work but will not receive new features.

| Legacy (deprecated) | Replacement |
|---|---|
| `ecdsa/keygen.NewLocalParty` | `ecdsatss.NewKeygen` |
| `ecdsa/keygen.GeneratePreParams` | `ecdsatss.GeneratePreParams` |
| `ecdsa/signing.NewLocalParty` | `ecdsatss.Key.NewSigning` |
| `ecdsa/resharing.NewLocalParty` | `ecdsatss.NewResharing` |
| `eddsa/keygen.NewLocalParty` | `eddsatss.NewKeygen` |
| `eddsa/signing.NewLocalParty` | `eddsatss.Key.NewSigning` |
| `eddsa/resharing.NewLocalParty` | `eddsatss.NewResharing` |

Key differences:
- **No channels**: Replace `outCh`/`endCh` with a `tss.MessageBroker` and `Done`/`Err` channels on the returned object.
- **No `Start()`/`Update()` loop**: The protocol runs automatically via broker callbacks.
- **No protobuf wire format**: Messages use JSON via `tss.JsonMessage`.
- **Key data**: `ecdsatss.Key` and `eddsatss.Key` have the same fields as the old `LocalPartySaveData` structs.

<details>
<summary>Legacy API usage (deprecated)</summary>

### Setup (Legacy)
```go
preParams, _ := keygen.GeneratePreParams(1 * time.Minute)
parties := tss.SortPartyIDs(getParticipantPartyIDs())
thisParty := tss.NewPartyID(id, moniker, uniqueKey)
ctx := tss.NewPeerContext(parties)
params := tss.NewParameters(tss.S256(), ctx, thisParty, len(parties), threshold)
```

### Keygen (Legacy)
```go
party := keygen.NewLocalParty(params, outCh, endCh, preParams)
go func() {
    err := party.Start()
    // handle err ...
}()
```

### Signing (Legacy)
```go
party := signing.NewLocalParty(message, params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

### Re-Sharing (Legacy)
```go
party := resharing.NewLocalParty(params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // handle err ...
}()
```

### Messaging (Legacy)
```go
// Receiving updates from other parties
party.UpdateFromBytes(wireBytes, from, isBroadcast)
// Getting wire bytes from outgoing messages
wireBytes, routing, err := msg.WireBytes()
```
</details>

## Changes of Preparams of ECDSA in v2.0

Two fields PaillierSK.P and PaillierSK.Q is added in version 2.0. They are used to generate Paillier key proofs. Key valuts generated from versions before 2.0 need to regenerate(resharing) the key valuts to update the praparams with the necessary fileds filled.

## How to use this securely

⚠️ This section is important. Be sure to read it!

The transport for messaging is left to the application layer and is not provided by this library. Each one of the following paragraphs should be read and followed carefully as it is crucial that you implement a secure transport to ensure safety of the protocol.

When you build a transport, it should offer a broadcast channel as well as point-to-point channels connecting every pair of parties. Your transport should also employ suitable end-to-end encryption (TLS with an [AEAD cipher](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) is recommended) between parties to ensure that a party can only read the messages sent to it.

Within your transport, each message should be wrapped with a **session ID** that is unique to a single run of the keygen, signing or re-sharing rounds. This session ID should be agreed upon out-of-band and known only by the participating parties before the rounds begin. Upon receiving any message, your program should make sure that the received session ID matches the one that was agreed upon at the start.

Additionally, there should be a mechanism in your transport to allow for "reliable broadcasts", meaning parties can broadcast a message to other parties such that it's guaranteed that each one receives the same message. There are several examples of algorithms online that do this by sharing and comparing hashes of received messages.

Timeouts and errors should be handled by your application. The method `WaitingFor` may be called on a `Party` to get the set of other parties that it is still waiting for messages from. You may also get the set of culprit parties that caused an error from a `*tss.Error`.

## Security Audit
A full review of this library was carried out by Kudelski Security and their final report was made available in October, 2019. A copy of this report [`audit-binance-tss-lib-final-20191018.pdf`](https://github.com/bnb-chain/tss-lib/releases/download/v1.0.0/audit-binance-tss-lib-final-20191018.pdf) may be found in the v1.0.0 release notes of this repository.

## References
\[1\] https://eprint.iacr.org/2019/114.pdf

\[2\] Borin, Celi, del Pino, Espitau, Niot, Prest. "Threshold Signatures Reloaded: ML-DSA and Enhanced Raccoon with Identifiable Aborts." ePrint 2025/1166 — https://eprint.iacr.org/2025/1166

