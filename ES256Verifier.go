package jwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
)

// ES256Verifier verifies JWT tokens using the ES256 algorithm.
type ES256Verifier struct {
	publicKey *ecdsa.PublicKey
}

var _ Verifier = &ES256Verifier{}

// NewES256Verifier creates a new ES256Verifier with the provided ECDSA Public
// Key.
func NewES256Verifier(publicKey *ecdsa.PublicKey) *ES256Verifier {
	return &ES256Verifier{
		publicKey: publicKey,
	}
}

// Verify verifies the provided serialized header and body against the provided
// signature.
func (v *ES256Verifier) Verify(b64HeaderAndBody string, signature []byte) bool {
	hashArr := sha256.Sum256([]byte(b64HeaderAndBody))
	hash := hashArr[:]

	if len(signature) != 64 {
		return false
	}

	rrp := signature[:32]
	srp := signature[32:]

	rbi := big.NewInt(0)
	sbi := big.NewInt(0)

	rbi.SetBytes(rrp)
	sbi.SetBytes(srp)

	return ecdsa.Verify(v.publicKey, hash, rbi, sbi)
}
