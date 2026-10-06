package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iabdulzahid/auth-token-server/internal/token"
)

// generateTestKey creates a 2048-bit RSA key for use in tests.
// Generating a key takes ~100ms. We generate it once per test file.
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// TestMintAndParseRoundTrip verifies that a token minted by MintAccessToken
// can be parsed back by ParseAccessToken and that all claims match.
func TestMintAndParseRoundTrip(t *testing.T) {
	key := generateTestKey(t)

	subject := "550e8400-e29b-41d4-a716-446655440000"
	subType := "user"
	scopes := []string{"read:orders", "write:orders"}
	kid := "test-kid-001"
	ttl := 15 * time.Minute

	tokenStr, err := token.MintAccessToken(key, kid, subject, subType, scopes, ttl)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}

	claims, err := token.ParseAccessToken(tokenStr, &key.PublicKey)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}

	if claims.Subject != subject {
		t.Errorf("sub: got %q, want %q", claims.Subject, subject)
	}
	if claims.Issuer != token.Issuer {
		t.Errorf("iss: got %q, want %q", claims.Issuer, token.Issuer)
	}
	if claims.SubType != subType {
		t.Errorf("sub_type: got %q, want %q", claims.SubType, subType)
	}
	if claims.Scope != "read:orders write:orders" {
		t.Errorf("scope: got %q, want %q", claims.Scope, "read:orders write:orders")
	}
	if claims.ID == "" {
		t.Error("jti claim must not be empty")
	}
	if claims.ExpiresAt == nil {
		t.Fatal("exp claim must be set")
	}
}

// TestMintAccessToken_KidInHeader verifies that the kid value is embedded in
// the JWT JOSE header, not just the claims body. Downstream JWKS verifiers
// look in the header, not the payload.
func TestMintAccessToken_KidInHeader(t *testing.T) {
	key := generateTestKey(t)
	kid := "deterministic-kid-abc"

	tokenStr, err := token.MintAccessToken(key, kid, "user-id", "user", nil, time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}

	// A JWT is three base64url parts separated by dots: header.payload.signature
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// The JOSE header is the first dot-separated part of the JWT, base64url-encoded.
	// Decode it and unmarshal the JSON to check the kid field.
	headerB64 := parts[0]
	// base64.RawURLEncoding handles JWT's unpadded base64url.
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal JWT header: %v", err)
	}
	gotKid, _ := header["kid"].(string)
	if gotKid != kid {
		t.Errorf("JWT header kid: got %q, want %q", gotKid, kid)
	}
	_ = strings.Contains // keep strings import used elsewhere in the file
}

// TestMintAccessToken_Expired verifies that ParseAccessToken rejects an
// already-expired token (negative TTL forces immediate expiry).
func TestMintAccessToken_Expired(t *testing.T) {
	key := generateTestKey(t)

	// Issue a token that expired 1 hour ago.
	tokenStr, err := token.MintAccessToken(key, "kid", "sub", "user", nil, -time.Hour)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}

	_, err = token.ParseAccessToken(tokenStr, &key.PublicKey)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

// TestMintAccessToken_WrongKey verifies that ParseAccessToken rejects a token
// verified with a different key than it was signed with.
func TestMintAccessToken_WrongKey(t *testing.T) {
	signingKey := generateTestKey(t)
	wrongKey := generateTestKey(t)

	tokenStr, err := token.MintAccessToken(signingKey, "kid", "sub", "user", nil, time.Minute)
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}

	_, err = token.ParseAccessToken(tokenStr, &wrongKey.PublicKey)
	if err == nil {
		t.Error("expected error when verifying with wrong key, got nil")
	}
}

// TestGenerateRefreshToken_Uniqueness verifies that two calls to
// GenerateRefreshToken never return the same raw token or hash.
func TestGenerateRefreshToken_Uniqueness(t *testing.T) {
	a, err := token.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	b, err := token.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}

	if a.Raw == b.Raw {
		t.Error("two calls produced the same raw token")
	}
	if a.Hash == b.Hash {
		t.Error("two calls produced the same hash")
	}
}

// TestGenerateRefreshToken_HashMatchesRaw verifies that HashRefreshToken
// reproduces the hash that was computed during generation.
func TestGenerateRefreshToken_HashMatchesRaw(t *testing.T) {
	pair, err := token.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}

	// Re-hash the raw token using the public helper.
	recomputed, err := token.HashRefreshToken(pair.Raw)
	if err != nil {
		t.Fatalf("HashRefreshToken: %v", err)
	}

	if recomputed != pair.Hash {
		t.Errorf("hash mismatch:\n  generated: %s\n  recomputed: %s", pair.Hash, recomputed)
	}
}

// TestHashRefreshToken_InvalidBase64 verifies that HashRefreshToken returns
// an error on malformed input rather than silently producing a wrong hash.
func TestHashRefreshToken_InvalidBase64(t *testing.T) {
	_, err := token.HashRefreshToken("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64 input, got nil")
	}
}

// TestMintAccessToken_JtiUnique verifies that each token has a unique jti.
func TestMintAccessToken_JtiUnique(t *testing.T) {
	key := generateTestKey(t)

	a, _ := token.MintAccessToken(key, "kid", "sub", "user", nil, time.Minute)
	b, _ := token.MintAccessToken(key, "kid", "sub", "user", nil, time.Minute)

	claimsA, _ := token.ParseAccessToken(a, &key.PublicKey)
	claimsB, _ := token.ParseAccessToken(b, &key.PublicKey)

	if claimsA.ID == claimsB.ID {
		t.Error("two tokens have the same jti — jti must be unique per issuance")
	}
}
