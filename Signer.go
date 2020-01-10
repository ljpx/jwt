package jwt

// Signer defines the methods that any JWT signer must implement.
type Signer interface {
	Algorithm() Algorithm
	Sign(b64HeaderAndBody string) ([]byte, error)
}
