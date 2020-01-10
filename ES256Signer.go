package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

// ES256Signer signs JWT tokens using the ES256 algorithm.
type ES256Signer struct {
	privateKey *ecdsa.PrivateKey
}

var _ Signer = &ES256Signer{}

// NewES256Signer creates a new ES256Signer with the provided ECDSA Private
// Key.
func NewES256Signer(privateKey *ecdsa.PrivateKey) *ES256Signer {
	return &ES256Signer{
		privateKey: privateKey,
	}
}

// Algorithm returns ES256.
func (s *ES256Signer) Algorithm() Algorithm {
	return ES256
}

// Sign signs the provided serialized header and body.
func (s *ES256Signer) Sign(b64HeaderAndBody string) ([]byte, error) {
	hashArr := sha256.Sum256([]byte(b64HeaderAndBody))
	hash := hashArr[:]

	rbi, sbi, err := ecdsa.Sign(rand.Reader, s.privateKey, hash)
	if err != nil {
		return nil, err
	}

	rr := rbi.Bytes()
	sr := sbi.Bytes()

	rrp := append(make([]byte, 32-len(rr)), rr...)
	srp := append(make([]byte, 32-len(sr)), sr...)

	return append(rrp, srp...), nil
}
