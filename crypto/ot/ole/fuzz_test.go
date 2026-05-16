package ole

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ot/otext"
)

// FuzzBobMsgParse feeds arbitrary bytes through the BobMsg JSON parser
// and the AliceStep2 entry-point validation. The invariant is "no
// panic" — malformed inputs must yield an error, not crash.
func FuzzBobMsgParse(f *testing.F) {
	seed := &BobMsg{
		Corrections: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
	}
	if b, err := json.Marshal(seed); err == nil {
		f.Add(b)
	}
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"corrections":[]}`))
	f.Add([]byte(`{"corrections":[null]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("BobMsg parse panicked on %q: %v", data, r)
			}
		}()
		var msg BobMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}
		// AliceStep2 nil-state path validates the message structure.
		_, _ = AliceStep2(nil, &msg)
	})
}

// FuzzExtendMsgInOLE wraps the upstream OT extension parser through
// the OLE code path.
func FuzzExtendMsgInOLE(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"L":256,"U":[],"x_check":"AA","t_check":"AA"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ExtendMsg parse panicked on %q: %v", data, r)
			}
		}()
		var msg otext.ExtendMsg1
		_ = json.Unmarshal(data, &msg)
	})
}
