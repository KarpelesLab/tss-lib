package dklstss

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// shareInflatingBroker wraps a test hubBroker and rewrites the round-1
// unicast share emitted by partyIdx to be `share + k·q` for some
// caller-chosen k. The total VSS commitment is unchanged so VSS.Verify
// still passes — pre-fix, this echo-bypass was accepted by every
// recipient. Post-fix, the explicit canonical-range check rejects it.
type shareInflatingBroker struct {
	*hubBroker
	q *big.Int
	k *big.Int
}

func (b *shareInflatingBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From != nil && msg.From.Index == b.partyIdx &&
		msg.Type == keygenTypeR1Unicast && msg.Data != nil {
		uc, ok := msg.Data.(*keygenR1Unicast)
		if ok && len(uc.Share) > 0 {
			cur := new(big.Int).SetBytes(uc.Share)
			cur.Add(cur, new(big.Int).Mul(b.q, b.k))
			mutated := *msg
			cloneUC := *uc
			cloneUC.Share = cur.Bytes()
			mutated.Data = &cloneUC
			return b.hubBroker.Receive(&mutated)
		}
	}
	return b.hubBroker.Receive(msg)
}

// TestKeygenRejectsNonCanonicalRound1Share verifies that a peer who ships
// `share + k·q` for k >= 1 is rejected at round 2. This guards against an
// echo-bypass channel where the dealer's per-recipient bytes can vary
// while the VSS verification (which reduces mod q internally) still
// passes.
func TestKeygenRejectsNonCanonicalRound1Share(t *testing.T) {
	const partyCount, threshold = 3, 1
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)

	q := tss.S256().Params().N

	// Wrap party 0's broker so its outgoing round-1 unicast shares are
	// inflated by +q (still valid mod q, but the wire encoding becomes
	// non-canonical).
	inflater := &shareInflatingBroker{
		hubBroker: hub.brokers[0],
		q:         q,
		k:         big.NewInt(1),
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*KeygenParty, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		if i == 0 {
			params.SetBroker(inflater)
		} else {
			params.SetBroker(hub.brokers[i])
		}
		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		parties[i] = kg
	}

	// At least one honest recipient must reject the non-canonical share.
	rejectCount := 0
	for i, p := range parties {
		if i == 0 {
			// The inflating party doesn't reject its own outputs.
			continue
		}
		select {
		case <-p.Done:
			t.Logf("party %d completed without rejecting non-canonical share", i)
		case err := <-p.Err:
			require.Error(t, err)
			require.Contains(t, err.Error(), "non-canonical")
			rejectCount++
			t.Logf("party %d correctly rejected with: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("party %d neither completed nor aborted", i)
		}
	}
	require.GreaterOrEqual(t, rejectCount, 1, "at least one party must reject the non-canonical share")
}
