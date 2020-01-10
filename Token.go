package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Token represents a (potentially signed) JWT token.
type Token struct {
	Header    Header
	Body      Body
	Signature []byte
}

// ErrInvalidTokenStructure is returned when the provided token has an invalid
// structure and is not semantically a JWT.
var ErrInvalidTokenStructure = errors.New("the provided token is invalid")

// ErrImmutable is returned when an operation cannot be completed due to the
// token being signed.
var ErrImmutable = errors.New("the operation cannot complete as the token is immutable")

// NewToken creates a new, empty, unsigned JWT.
func NewToken() *Token {
	return &Token{
		Header:    NewHeader(),
		Body:      Body{},
		Signature: nil,
	}
}

// AddScope adds a scope to the token.  This operation is a no-op if the token
// is signed.
func (t *Token) AddScope(scope string) {
	if t.IsSigned() {
		return
	}

	scope = strings.TrimSpace(scope)
	scopes, _ := t.Body["scope"].([]string)

	scopes = append(scopes, scope)
	t.Body["scope"] = scopes
}

// RemoveScope removes a scope from the token.  This operation is a no-op if the
// token is signed.
func (t *Token) RemoveScope(scope string) {
	if t.IsSigned() {
		return
	}

	scope = strings.TrimSpace(scope)

	scopes, ok := t.Body["scope"].([]string)
	if !ok {
		return
	}

	for i, v := range scopes {
		if v == scope {
			scopes[i], scopes[len(scopes)-1] = scopes[len(scopes)-1], scopes[i]
			t.Body["scope"] = scopes[:len(scopes)-1]
			break
		}
	}
}

// HasScope returns true if the token has the provided scope.
func (t *Token) HasScope(scope string) bool {
	scopes, ok := t.Body["scope"].([]string)
	if !ok {
		return false
	}

	for _, v := range scopes {
		if v == scope {
			return true
		}
	}

	return false
}

// AddClaim adds a claim to the token.
func (t *Token) AddClaim(name string, value interface{}) {
	if name == "scope" {
		return
	}

	t.Body[name] = value
}

// RemoveClaim removes a claim from the token.
func (t *Token) RemoveClaim(name string) {
	if name == "scope" {
		return
	}

	delete(t.Body, name)
}

// GetClaim gets the value of a claim, if present.
func (t *Token) GetClaim(name string) (interface{}, bool) {
	if name == "scope" {
		return nil, false
	}

	value, ok := t.Body[name]
	return value, ok
}

// GetStringClaim gets the string value of a claim, if present.
func (t *Token) GetStringClaim(name string) (string, bool) {
	value, ok := t.GetClaim(name)
	if !ok {
		return "", false
	}

	str, ok := value.(string)
	return str, ok
}

// IsSigned returns true when the token has a signature present.  This method
// does not state anything about the validity of an attached signature.
func (t *Token) IsSigned() bool {
	return t.Signature != nil
}

// Sign signs the token with the provided Signer.
func (t *Token) Sign(signer Signer) error {
	if t.IsSigned() {
		return ErrImmutable
	}

	newHeader := Header{
		Type:      t.Header.Type,
		Algorithm: signer.Algorithm(),
	}

	b64HeaderAndBody, err := serializeHeaderAndBody(newHeader, t.Body)
	if err != nil {
		return err
	}

	signature, err := signer.Sign(b64HeaderAndBody)
	if err != nil {
		return err
	}

	t.Header = newHeader
	t.Signature = signature
	return nil
}

// Verify verifies the signature on the token, if present, using the provided
// verifier.
func (t *Token) Verify(verifier Verifier) bool {
	if !t.IsSigned() {
		return false
	}

	b64HeaderAndBody, err := serializeHeaderAndBody(t.Header, t.Body)
	if err != nil {
		return false
	}

	return verifier.Verify(b64HeaderAndBody, t.Signature)
}

// Serialize serializes the token to its string form.
func (t *Token) Serialize() (string, error) {
	b64HeaderAndBody, err := serializeHeaderAndBody(t.Header, t.Body)
	if err != nil {
		return "", err
	}

	b64Signature := base64.RawURLEncoding.EncodeToString(t.Signature)

	return fmt.Sprintf("%v.%v", b64HeaderAndBody, b64Signature), nil
}

// Parse parses the provided string token.
func Parse(tokenString string) (*Token, error) {
	spl := strings.Split(tokenString, ".")
	if len(spl) != 3 {
		return nil, ErrInvalidTokenStructure
	}

	rawHeader, err := base64.RawURLEncoding.DecodeString(spl[0])
	if err != nil {
		return nil, err
	}

	rawBody, err := base64.RawURLEncoding.DecodeString(spl[1])
	if err != nil {
		return nil, err
	}

	rawSignature, err := base64.RawURLEncoding.DecodeString(spl[2])
	if err != nil {
		return nil, err
	}

	header := Header{}
	err = json.Unmarshal(rawHeader, &header)
	if err != nil {
		return nil, err
	}

	body := Body{}
	err = json.Unmarshal(rawBody, &body)
	if err != nil {
		return nil, err
	}

	return &Token{
		Header:    header,
		Body:      body,
		Signature: rawSignature,
	}, nil
}

func serializeHeaderAndBody(header Header, body Body) (string, error) {
	rawHeader, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	rawBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	b64Header := base64.RawURLEncoding.EncodeToString(rawHeader)
	b64Body := base64.RawURLEncoding.EncodeToString(rawBody)

	return fmt.Sprintf("%v.%v", b64Header, b64Body), nil
}
