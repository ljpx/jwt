package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/ljpx/test"
)

func TestTokenSerializeAndParse(t *testing.T) {
	// Arrange.
	token1 := &Token{
		Header: Header{Algorithm: ES256, Type: "JWT"},
		Body: map[string]interface{}{
			"Key1": "Value1",
			"Key2": "Value2",
		},
		Signature: []byte{1, 2, 3, 4},
	}

	// Act.
	tokenString, err := token1.Serialize()
	test.That(t, err).IsNil()

	token2, err := Parse(tokenString)
	test.That(t, err).IsNil()

	// Assert.
	test.That(t, token2.Header.Algorithm).IsEqualTo(ES256)
	test.That(t, token2.Body["Key1"]).IsEqualTo("Value1")
	test.That(t, token2.Body["Key2"]).IsEqualTo("Value2")
	test.That(t, token2.Signature).HasEquivalentSequenceTo([]byte{1, 2, 3, 4})
}

func TestTokenSignAndVerify(t *testing.T) {
	// Arrange.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.That(t, err).IsNil()

	signer := NewES256Signer(privateKey)
	verifier := NewES256Verifier(&privateKey.PublicKey)

	token := &Token{
		Header: Header{Algorithm: None, Type: "JWT"},
		Body: map[string]interface{}{
			"Key1": "Value1",
			"Key2": "Value2",
		},
	}

	// Act.
	err = token.Sign(signer)
	test.That(t, err).IsNil()

	valid := token.Verify(verifier)

	// Assert.
	test.That(t, valid).IsTrue()
}

func TestTokenScopes(t *testing.T) {
	// Arrange.
	token := NewToken()

	// Act.
	token.AddScope("user:create")
	token.AddScope("user:delete")

	hasDelete := token.HasScope("user:delete")
	hasRead := token.HasScope("user:read")

	token.RemoveScope("user:delete")

	// Assert.
	test.That(t, hasDelete).IsTrue()
	test.That(t, hasRead).IsFalse()

	scopes, ok := token.Body["scope"]
	test.That(t, ok).IsTrue()
	test.That(t, scopes).HasEquivalentSequenceTo([]string{"user:create"})
}

func TestTokenScopesImmutableWhenSigned(t *testing.T) {
	// Arrange.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.That(t, err).IsNil()

	signer := NewES256Signer(privateKey)

	token := NewToken()
	token.AddScope("user:create")

	err = token.Sign(signer)
	test.That(t, err).IsNil()
	test.That(t, token.IsSigned()).IsTrue()

	// Assert.
	token.AddScope("user:delete")
	token.RemoveScope("user:create")

	test.That(t, token.HasScope("user:delete")).IsFalse()
	test.That(t, token.HasScope("user:create")).IsTrue()
}

func TestTokenAddClaimCannotInteractWithScope(t *testing.T) {
	// Arrange.
	token := NewToken()

	// Act.
	token.AddClaim("scope", []string{"user:create"})

	// Assert.
	test.That(t, token.HasScope("user:create")).IsFalse()
}

func TestTokenRemoveClaimCannotInteractWithScope(t *testing.T) {
	// Arrange.
	token := NewToken()

	// Act.
	token.AddScope("user:delete")
	token.RemoveClaim("scope")

	// Assert.
	test.That(t, token.HasScope("user:delete")).IsTrue()
}

func TestTokenGetClaimCannotGetScopes(t *testing.T) {
	// Arrange.
	token := NewToken()

	// Act.
	token.AddScope("user:read")

	// Assert.
	value, ok := token.GetClaim("scope")
	test.That(t, value).IsNil()
	test.That(t, ok).IsFalse()
}

func TestTokenClaims(t *testing.T) {
	// Arrange.
	token := NewToken()

	// Act.
	token.AddClaim("iss", "Test Issuer")
	token.AddClaim("exp", 86400)
	token.RemoveClaim("exp")

	// Assert.
	iss, ok := token.GetStringClaim("iss")
	test.That(t, ok).IsTrue()
	test.That(t, iss).IsEqualTo("Test Issuer")

	exp, ok := token.GetClaim("exp")
	test.That(t, ok).IsFalse()
	test.That(t, exp).IsNil()
}

func TestTokenE2E(t *testing.T) {
	// Arrange.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.That(t, err).IsNil()

	publicKey := &privateKey.PublicKey

	signer := NewES256Signer(privateKey)
	verifier := NewES256Verifier(publicKey)

	token := NewToken()
	token.AddClaim("iss", "Test Issuer")
	token.AddScope("user:create")
	token.AddScope("user:delete")

	// Act.
	err = token.Sign(signer)
	test.That(t, err).IsNil()

	valid := token.Verify(verifier)

	// Output.
	serialized, err := token.Serialize()
	test.That(t, err).IsNil()

	rawPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	test.That(t, err).IsNil()

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rawPublicKey,
	}

	pem := string(pem.EncodeToMemory(pemBlock))

	fmt.Printf("\n\n%v\n\n", pem)
	fmt.Printf("%v\n\n", serialized)

	// Assert.
	test.That(t, valid).IsTrue()
}
