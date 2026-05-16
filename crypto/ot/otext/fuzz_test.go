package otext

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"
)

// FuzzExtendMsgJSON parses arbitrary bytes as an ExtendMsg1 JSON
// payload and feeds the result to the sender's Extend. The invariant
// is "no panic": malformed inputs must return an error, not crash the
// process.
func FuzzExtendMsgJSON(f *testing.F) {
	// Seed: a valid extension message we recompute once.
	sid := []byte("fuzz-seed")
	extSender, extReceiver, _ := mustSetup(f, sid)
	choice := []byte{0xAA, 0x55}
	msg, _, err := extReceiver.Extend(sid, choice, 16)
	if err != nil {
		f.Fatalf("setup: %v", err)
	}
	b, err := json.Marshal(msg)
	if err != nil {
		f.Fatalf("setup marshal: %v", err)
	}
	f.Add(b)
	// Add a few obviously-bad seeds.
	f.Add([]byte("{}"))
	f.Add([]byte("[]"))
	f.Add([]byte("null"))
	f.Add([]byte("{\"L\": -1}"))
	f.Add([]byte("{\"L\": 4096, \"U\": []}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Extend panicked on input %q: %v", data, r)
			}
		}()
		var msg ExtendMsg1
		if err := json.Unmarshal(data, &msg); err != nil {
			return // malformed JSON; ignore
		}
		// Cap L to avoid OOM on adversarial sizes.
		if msg.L > 1024 {
			return
		}
		_, _, _ = extSender.Extend(sid, &msg)
	})
}

// mustSetup is a fuzz-test helper that produces matched ExtSender/ExtReceiver.
func mustSetup(f *testing.F, sid []byte) (*ExtSender, *ExtReceiver, []byte) {
	f.Helper()
	boSender, smsg, err := baseot.NewSender(sid, Kappa, rand.Reader)
	if err != nil {
		f.Fatalf("base OT sender: %v", err)
	}
	delta := make([]byte, DeltaBytes)
	if _, err := rand.Read(delta); err != nil {
		f.Fatalf("delta rand: %v", err)
	}
	boReceiver, rmsg, err := baseot.NewReceiver(sid, Kappa, delta, smsg, rand.Reader)
	if err != nil {
		f.Fatalf("base OT receiver: %v", err)
	}
	k0, k1, err := boSender.Finalize(rmsg)
	if err != nil {
		f.Fatalf("sender finalize: %v", err)
	}
	chosen, err := boReceiver.Finalize()
	if err != nil {
		f.Fatalf("receiver finalize: %v", err)
	}
	extReceiver, err := NewExtReceiverFromBase(k0, k1)
	if err != nil {
		f.Fatalf("ext receiver: %v", err)
	}
	extSender, err := NewExtSenderFromBase(delta, chosen)
	if err != nil {
		f.Fatalf("ext sender: %v", err)
	}
	return extSender, extReceiver, delta
}
