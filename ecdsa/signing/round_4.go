// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

func (round *round4) Start() error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	theta := *round.temp.theta
	thetaInverse := &theta

	modN := common.ModInt(round.Params().EC().Params().N)

	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		thetaJ := r3msg.GetTheta()
		thetaInverse = modN.Add(thetaInverse, new(big.Int).SetBytes(thetaJ))
	}

	// compute the multiplicative inverse of theta mod q
	thetaInverse = modN.ModInverse(thetaInverse)
	if thetaInverse == nil {
		// a malicious coalition can drive the aggregate theta to 0 mod q, in
		// which case it has no inverse; abort cleanly instead of panicking
		// later when R is scaled by a nil thetaInverse.
		return round.WrapError(errors.New("theta is not invertible mod q"), round.PartyID())
	}
	i := round.PartyID().Index
	ContextI := append(round.temp.ssid, new(big.Int).SetUint64(uint64(i)).Bytes()...)
	piGamma, err := schnorr.NewZKProof(ContextI, round.temp.gamma, round.temp.pointGamma, round.Rand())
	if err != nil {
		return round.WrapError(fmt.Errorf("NewZKProof(gamma, bigGamma): %w", err))
	}
	round.temp.thetaInverse = thetaInverse
	r4msg := NewSignRound4Message(round.PartyID(), round.temp.deCommit, piGamma)
	round.temp.signRound4Messages[round.PartyID().Index] = r4msg
	round.out <- r4msg

	return nil
}

func (round *round4) Update() (bool, error) {
	ret := true
	for j, msg := range round.temp.signRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
