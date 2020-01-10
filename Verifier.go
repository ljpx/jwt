package jwt

// Verifier defines the methods that any JWT signature verifier must implement.
type Verifier interface {
	Verify(b64HeaderAndBody string, signature []byte) bool
}
