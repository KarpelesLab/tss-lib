// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"math/big"
)

const (
	mustGetRandomIntMaxBits = 5000
)

// MustGetRandomInt panics if it is unable to gather entropy from `io.Reader` or when `bits` is <= 0
func MustGetRandomInt(rand io.Reader, bits int) *big.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := cryptorand.Int(rand, max)
	if err != nil {
		panic(fmt.Errorf("rand.Int failure in MustGetRandomInt: %w", err))
	}
	return n
}

// GetRandomPositiveInt returns a random strictly positive integer less
// than the given upper bound — i.e. uniformly sampled from [1, lessThan).
//
// The "Positive" in the name historically permitted 0; cryptographic
// callers (curve scalars, blinding factors, signing nonces) almost
// universally need 0 excluded. The probability of accidentally landing
// on 0 is 1/lessThan ≈ 2^{-256} for curve-order moduli, so existing
// callers are unaffected in practice; the rejection closes a latent
// foot-gun without a meaningful performance cost.
func GetRandomPositiveInt(rand io.Reader, lessThan *big.Int) *big.Int {
	if lessThan == nil || zero.Cmp(lessThan) != -1 {
		return nil
	}
	if lessThan.Cmp(one) <= 0 {
		// No positive integer < 1 exists.
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(rand, lessThan.BitLen())
		if try.Sign() == 0 {
			continue
		}
		if try.Cmp(lessThan) < 0 {
			break
		}
	}
	return try
}

// GetRandomPrimeInt returns a random prime number of the specified bit length.
func GetRandomPrimeInt(rand io.Reader, bits int) *big.Int {
	if bits <= 0 {
		return nil
	}
	try, err := cryptorand.Prime(rand, bits)
	if err != nil ||
		try.Cmp(zero) == 0 {
		// fallback to older method
		for {
			try = MustGetRandomInt(rand, bits)
			if probablyPrime(try) {
				break
			}
		}
	}
	return try
}

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomPositiveRelativelyPrimeInt(rand io.Reader, n *big.Int) *big.Int {
	if n == nil || zero.Cmp(n) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(rand, n.BitLen())
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}
	return try
}

// IsNumberInMultiplicativeGroup returns true if v is in the multiplicative group of integers modulo n.
func IsNumberInMultiplicativeGroup(n, v *big.Int) bool {
	if n == nil || v == nil || zero.Cmp(n) != -1 {
		return false
	}
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

//	Return a random generator of RQn with high probability.
//	THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
//
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(rand io.Reader, n *big.Int) *big.Int {
	f := GetRandomPositiveRelativelyPrimeInt(rand, n)
	fSq := new(big.Int).Mul(f, f)
	return fSq.Mod(fSq, n)
}

// GetRandomQuadraticNonResidue returns a quadratic non residue of odd n.
func GetRandomQuadraticNonResidue(rand io.Reader, n *big.Int) *big.Int {
	for {
		w := GetRandomPositiveInt(rand, n)
		if big.Jacobi(w, n) == -1 {
			return w
		}
	}
}

// GetRandomBytes returns random bytes of length.
func GetRandomBytes(rand io.Reader, length int) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length <= 0 {
		return nil, fmt.Errorf("invalid random bytes length: %d", length)
	}
	if rand == nil {
		rand = cryptorand.Reader
	}

	buf := make([]byte, length)
	_, err := io.ReadFull(rand, buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
