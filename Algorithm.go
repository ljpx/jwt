package jwt

// Algorithm is an alias for string that defines the set of supported JWT
// signature types.
type Algorithm string

// The supported signature types.
const (
	None  Algorithm = "None"
	ES256 Algorithm = "ES256"
)
