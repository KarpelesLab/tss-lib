package dklstss

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Keygen runs the in-process DKG; AsyncKeygen wraps it with the
// Done/Err channel idiom used by ecdsatss/eddsatss/frosttss so callers
// can compose dklstss into existing async pipelines without changing
// surrounding code shape.
//
// NOTE: this is NOT a distributed-protocol broker integration. All
// parties run in the caller's process. A real distributed wiring with
// per-party message routing remains a future task (see package doc).
type AsyncKeygen struct {
	Done chan []*Key
	Err  chan error
}

// NewAsyncKeygen launches a DKG asynchronously. The returned struct's
// Done channel receives the per-party Key slice on success; Err receives
// the first error encountered.
//
// The returned channels each have capacity 1; the goroutine sends to
// exactly one before exiting.
func NewAsyncKeygen(ctx context.Context, n, t int, partyIDs tss.SortedPartyIDs, rng io.Reader) *AsyncKeygen {
	a := &AsyncKeygen{
		Done: make(chan []*Key, 1),
		Err:  make(chan error, 1),
	}
	if rng == nil {
		rng = rand.Reader
	}
	go func() {
		keys, err := Keygen(n, t, partyIDs, rng)
		// Respect context cancellation as a best-effort gate; the
		// underlying Keygen does not currently accept a context, so
		// cancellation after launch will still let Keygen complete and
		// send the result (which the caller can then ignore).
		select {
		case <-ctx.Done():
			a.Err <- ctx.Err()
			return
		default:
		}
		if err != nil {
			a.Err <- err
			return
		}
		a.Done <- keys
	}()
	return a
}

// AsyncSigning is the analogous async wrapper for Sign.
type AsyncSigning struct {
	Done chan *Signature
	Err  chan error
}

// NewAsyncSigning launches the signing protocol asynchronously.
func NewAsyncSigning(ctx context.Context, keys []*Key, signerIdx []int, hash []byte, rng io.Reader) *AsyncSigning {
	a := &AsyncSigning{
		Done: make(chan *Signature, 1),
		Err:  make(chan error, 1),
	}
	if rng == nil {
		rng = rand.Reader
	}
	go func() {
		sig, err := Sign(keys, signerIdx, hash, rng)
		select {
		case <-ctx.Done():
			a.Err <- ctx.Err()
			return
		default:
		}
		if err != nil {
			a.Err <- err
			return
		}
		a.Done <- sig
	}()
	return a
}

// AsyncPresign is the async wrapper for Presign.
type AsyncPresign struct {
	Done chan *PresignOutput
	Err  chan error
}

// NewAsyncPresign launches the pre-signing phase asynchronously.
func NewAsyncPresign(ctx context.Context, keys []*Key, signerIdx []int, rng io.Reader) *AsyncPresign {
	a := &AsyncPresign{
		Done: make(chan *PresignOutput, 1),
		Err:  make(chan error, 1),
	}
	if rng == nil {
		rng = rand.Reader
	}
	go func() {
		out, err := Presign(keys, signerIdx, rng)
		select {
		case <-ctx.Done():
			a.Err <- ctx.Err()
			return
		default:
		}
		if err != nil {
			a.Err <- err
			return
		}
		a.Done <- out
	}()
	return a
}

// AsyncRefresh is the async wrapper for Refresh.
type AsyncRefresh struct {
	Done chan []*Key
	Err  chan error
}

// NewAsyncRefresh launches proactive refresh asynchronously.
func NewAsyncRefresh(ctx context.Context, keys []*Key, rng io.Reader) *AsyncRefresh {
	a := &AsyncRefresh{
		Done: make(chan []*Key, 1),
		Err:  make(chan error, 1),
	}
	if rng == nil {
		rng = rand.Reader
	}
	go func() {
		out, err := Refresh(keys, rng)
		select {
		case <-ctx.Done():
			a.Err <- ctx.Err()
			return
		default:
		}
		if err != nil {
			a.Err <- err
			return
		}
		a.Done <- out
	}()
	return a
}

// Keep math/big referenced so the import resolves; we use it via PartyID
// elsewhere.
var _ = big.NewInt
