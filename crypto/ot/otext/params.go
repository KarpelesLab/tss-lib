package otext

import "github.com/KarpelesLab/tss-lib/v2/crypto/ot/baseot"

// Security parameters for the OT extension. These are exported as named
// constants so reviewers can audit the security claim and dependencies
// (downstream protocols) can reference them rather than hard-coding sizes.
const (
	// Kappa is the computational security parameter in bits. κ=128 is
	// the standard target for malicious-secure OT extension built on
	// AES-128 as the PRG.
	Kappa = 128

	// DeltaBytes is the byte length of the OT extension sender's global
	// correlation Δ ∈ {0,1}^κ.
	DeltaBytes = Kappa / 8

	// Sigma is the statistical security parameter (bits) used by the
	// consistency check. Roy 2022 §6 uses σ=80 for typical deployments;
	// the consistency check itself is task #16. We keep the constant
	// here so the semi-honest API can be migrated without renaming.
	Sigma = 80

	// SeedLen is the byte length of the PRG seed derived from each base
	// OT instance. It equals baseot.KeyLen.
	SeedLen = baseot.KeyLen

	// KeyLen is the byte length of each output OT key. Equal to a full
	// SHA-512/256 output.
	KeyLen = 32
)
