package keys_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/iabdulzahid/auth-token-server/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestKey creates a 2048-bit RSA key pair for use in tests.
// We generate the key in-process rather than using a hardcoded PEM string because:
//   - A hardcoded key in a test file is a secret committed to git.
//   - In-process generation ensures the test works without any external files.
//   - 2048-bit generation is fast enough for tests (~50ms).
func generateTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode as PKCS#1 PEM — the format produced by `openssl genrsa`
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, string(pemBytes)
}

// TestParsePrivateKey_PKCS1 verifies that a PKCS#1 PEM-encoded key is parsed correctly.
func TestParsePrivateKey_PKCS1(t *testing.T) {
	original, pemStr := generateTestKey(t)

	parsed, err := keys.ParsePrivateKey(pemStr)
	require.NoError(t, err)

	// The parsed key must be mathematically identical to the original.
	assert.Equal(t, original.N, parsed.N)
	assert.Equal(t, original.E, parsed.E)
}

// TestParsePrivateKey_PKCS8 verifies that a PKCS#8 PEM-encoded key is also accepted.
func TestParsePrivateKey_PKCS8(t *testing.T) {
	original, _ := generateTestKey(t)

	// Re-encode as PKCS#8
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(original)
	require.NoError(t, err)

	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}))

	parsed, err := keys.ParsePrivateKey(pemStr)
	require.NoError(t, err)
	assert.Equal(t, original.N, parsed.N)
}

// TestParsePrivateKey_EmptyPEM verifies that missing PEM data returns a clear error.
func TestParsePrivateKey_EmptyPEM(t *testing.T) {
	_, err := keys.ParsePrivateKey("not a pem string")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM data found")
}

// TestParsePrivateKey_WrongType verifies that a non-RSA PEM block returns a clear error.
func TestParsePrivateKey_WrongType(t *testing.T) {
	garbage := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not a key"),
	}))
	_, err := keys.ParsePrivateKey(garbage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported PEM block type")
}

// TestDeriveKID_Deterministic verifies that the same key always produces the same kid.
// This is the core property that makes kid safe to use in production —
// restarts and replicas all produce the same value for the same key.
func TestDeriveKID_Deterministic(t *testing.T) {
	_, pemStr := generateTestKey(t)

	key, err := keys.ParsePrivateKey(pemStr)
	require.NoError(t, err)

	kid1 := keys.DeriveKID(&key.PublicKey)
	kid2 := keys.DeriveKID(&key.PublicKey)

	assert.Equal(t, kid1, kid2, "same key must always produce the same kid")
	assert.NotEmpty(t, kid1)
}

// TestDeriveKID_DifferentKeys verifies that two different keys produce different kids.
// This prevents kid collisions when multiple keys are in use (e.g. during rotation).
func TestDeriveKID_DifferentKeys(t *testing.T) {
	_, pemStr1 := generateTestKey(t)
	_, pemStr2 := generateTestKey(t)

	key1, _ := keys.ParsePrivateKey(pemStr1)
	key2, _ := keys.ParsePrivateKey(pemStr2)

	kid1 := keys.DeriveKID(&key1.PublicKey)
	kid2 := keys.DeriveKID(&key2.PublicKey)

	assert.NotEqual(t, kid1, kid2, "different keys must produce different kids")
}

// TestBuildJWKS_Shape verifies that the JWKS document has the correct structure
// and contains all required fields for downstream JWT verification.
func TestBuildJWKS_Shape(t *testing.T) {
	_, pemStr := generateTestKey(t)
	key, err := keys.ParsePrivateKey(pemStr)
	require.NoError(t, err)

	kid := keys.DeriveKID(&key.PublicKey)
	jwksBytes, err := keys.BuildJWKS(&key.PublicKey, kid)
	require.NoError(t, err)

	// Unmarshal into a generic map to inspect the raw JSON shape.
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(jwksBytes, &doc))

	// Top-level must have "keys" array.
	keysArr, ok := doc["keys"].([]interface{})
	require.True(t, ok, "JWKS must have a 'keys' array")
	require.Len(t, keysArr, 1, "must contain exactly one key")

	jwk := keysArr[0].(map[string]interface{})

	// Every field required by RFC 7517 for RSA signature verification must be present.
	assert.Equal(t, "RSA", jwk["kty"], "kty must be RSA")
	assert.Equal(t, "sig", jwk["use"], "use must be sig")
	assert.Equal(t, "RS256", jwk["alg"], "alg must be RS256")
	assert.Equal(t, kid, jwk["kid"], "kid must match derived kid")
	assert.NotEmpty(t, jwk["n"], "modulus n must be present")
	assert.NotEmpty(t, jwk["e"], "exponent e must be present")
}

// TestBuildJWKS_ValidJSON verifies the output is valid JSON.
func TestBuildJWKS_ValidJSON(t *testing.T) {
	_, pemStr := generateTestKey(t)
	key, _ := keys.ParsePrivateKey(pemStr)
	kid := keys.DeriveKID(&key.PublicKey)

	jwksBytes, err := keys.BuildJWKS(&key.PublicKey, kid)
	require.NoError(t, err)
	assert.True(t, json.Valid(jwksBytes), "JWKS output must be valid JSON")
}
