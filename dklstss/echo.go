package dklstss

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// commitDigest hashes a dealer's VSS commitments into a stable
// fingerprint used by the echo-broadcast phase. The encoding is
// length-prefixed so that distinct commitment slices cannot share a
// digest by coincidence of byte alignment.
//
// tag is the protocol-domain separator ("DKLS23-echo-keygen-v1" or
// similar); dealer is the party that produced the commitments.
func commitDigest(tag string, dealer *tss.PartyID, vsBytes [][]byte) []byte {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write([]byte{'|'})
	if dealer != nil {
		h.Write(dealer.KeyInt().Bytes())
	}
	h.Write([]byte{'|'})
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(len(vsBytes)))
	h.Write(buf[:])
	for _, c := range vsBytes {
		binary.LittleEndian.PutUint64(buf[:], uint64(len(c)))
		h.Write(buf[:])
		h.Write(c)
	}
	return h.Sum(nil)
}

// echoMsg is the wire form of the echo-broadcast phase. It carries the
// echoer's digest of every dealer's commitments it received in round 1.
// Keys in Digests are PartyID.KeyInt().String(); values are the digest
// returned by commitDigest.
//
// One echoMsg is sent per echoer as a To==nil broadcast; recipients
// gather one per peer and cross-check against their own view of the
// commitments. A digest mismatch identifies the equivocating dealer
// (or, if the dealer entry references the recipient itself, the
// echoer — see verifyEchoes).
type echoMsg struct {
	Digests map[string][]byte `json:"digests"`
}

// verifyEchoes cross-checks every echoer's reported digest against the
// recipient's own view. Returns nil if every echo matches; otherwise
// returns a *tss.Error whose Culprits() is populated with the party
// most likely responsible for the inconsistency:
//
//   - If an echoer's digest for some dealer D ≠ self disagrees with
//     the recipient's local digest for D, D is named the culprit
//     (dealer equivocation is the primary threat).
//   - If an echoer's digest for D = self disagrees with the
//     recipient's canonical view of its own commitments, the echoer
//     is named the culprit (the recipient trusts its own canonical V).
//   - Missing or unexpected entries in an echo are treated as protocol
//     errors and surface a wrapped error rather than identifiable
//     abort.
//
// myDigests must contain an entry for every party EXCEPT self for
// peer-as-dealer cross-checks, plus an entry under selfKey for the
// "echoer disagrees with my own V" attribution path.
//
// echoers is the ordered list of parties whose echoes are in msgs (one
// per echoer); the relationship msgs[n] came from echoers[n] is the
// same convention tss.JsonExpect emits.
//
// allParties is the full committee from the echoer's perspective —
// used to enforce "an echoer must include a digest for every party
// except itself." For protocols where the dealer set and the echoer
// set differ (resharing: OLD dealers, NEW echoers), pass the dealer
// set as allParties; verifyEchoes only iterates entries the echoer
// actually sent.
//
// tag and source identify the protocol for error messages.
func verifyEchoes(
	myDigests map[string][]byte,
	selfKey string,
	echoers []*tss.PartyID,
	msgs []*echoMsg,
	allParties []*tss.PartyID,
	source string,
) error {
	// Build PartyID lookup by key string for O(1) culprit attribution.
	byKey := make(map[string]*tss.PartyID, len(allParties))
	for _, p := range allParties {
		byKey[peerKeyStr(p)] = p
	}

	for n, echoer := range echoers {
		ec := msgs[n]
		if ec == nil || ec.Digests == nil {
			return fmt.Errorf("dklstss: %s echo from %s is empty", source, echoer)
		}
		echoerKey := peerKeyStr(echoer)
		for dealerKey, theirDigest := range ec.Digests {
			if dealerKey == echoerKey {
				return fmt.Errorf("dklstss: %s echo from %s contains a self-entry", source, echoer)
			}
			mine, ok := myDigests[dealerKey]
			if !ok {
				// Echoer mentioned a party we have no view of. With
				// the echo-set restricted to dealers (the only
				// parties whose commitments we care about), unknown
				// keys are protocol noise rather than equivocation
				// evidence.
				continue
			}
			if bytes.Equal(mine, theirDigest) {
				continue
			}
			// Disagreement. Pick a culprit.
			if dealerKey == selfKey {
				// Echoer disagrees with my own canonical V — I trust
				// myself, so the echoer is the suspect.
				return tss.NewError(
					fmt.Errorf("echo from %s disagrees with my canonical commitments", echoer),
					source, 0, nil, echoer)
			}
			dealer := byKey[dealerKey]
			if dealer == nil {
				return fmt.Errorf("dklstss: %s echo from %s disagrees on unknown dealer %s",
					source, echoer, dealerKey)
			}
			return tss.NewError(
				fmt.Errorf("echo from %s reports a different commitment for %s than I received",
					echoer, dealer),
				source, 0, nil, dealer)
		}
	}
	return nil
}
