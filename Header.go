package jwt

// Header represents a JWT header.
type Header struct {
	Algorithm Algorithm `json:"alg"`
	Type      string    `json:"typ"`
}

// NewHeader creates a new Header.
func NewHeader() Header {
	return Header{
		Algorithm: None,
		Type:      "JWT",
	}
}
