// Package token handles all JWT minting and opaque refresh token generation
// for the Auth Token Server.
//
// # Access tokens (JWTs)
//
// Access tokens are short-lived (default 15 minutes), RS256-signed JWTs.
// They are self-contained: a downstream service can validate the signature
// and read the claims without contacting the ATS. The claims embedded are:
//
//	sub       — UUID of the authenticated user or service account
//	iss       — "auth-token-server" (constant issuer string)
//	iat       — issued-at unix timestamp
//	exp       — expiry unix timestamp (iat + TTL)
//	jti       — unique token ID (UUID v4) — used for future revocation/audit
//	scope     — space-separated scopes (RFC 6749 §3.3)
//	sub_type  — "user" or "service_account" — disambiguates the subject
//
// # Refresh tokens
//
// Refresh tokens are opaque 32-byte random values, base64url-encoded.
// They are NOT JWTs — they carry no claims and cannot be decoded by the client.
// The raw value is returned to the client exactly once; we store only its
// SHA-256 hash in Postgres. If the database is compromised, the hashes
// cannot be used directly.
//
// # Why store only the hash?
//
// SHA-256 is a one-way function. An attacker who reads the database sees only
// hashes. Without the raw token (which was never stored), they cannot use the
// hash to authenticate. This is the same principle as bcrypt for passwords,
// but SHA-256 is appropriate here because the input (32 bytes of crypto/rand)
// has enough entropy that a brute-force preimage attack is computationally
// infeasible, unlike low-entropy passwords.
package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Issuer is the value placed in the "iss" claim of every access token.
// Downstream services can assert this value to reject tokens from unknown issuers.
const Issuer = "auth-token-server"

// Claims is the full set of JWT claims embedded in an access token.
// It embeds jwt.RegisteredClaims (sub, iss, iat, exp, jti) and adds two
// ATS-specific claims: Scope and SubType.
type Claims struct {
	jwt.RegisteredClaims

	// Scope is a space-separated string of granted permission scopes.
	// RFC 6749 §3.3 defines this format. Downstream services split on spaces
	// to get a list: strings.Fields(claims.Scope).
	Scope string `json:"scope"`

	// SubType tells a downstream service whether the subject is a human user
	// or a machine service account. Without this claim, a service would need
	// to look up the UUID in a database to know which table it references.
	// With it, the JWT is fully self-describing.
	SubType string `json:"sub_type"`
}

// MintAccessToken creates and signs an RS256 JWT access token.
//
// Parameters:
//   - key: the RSA private key loaded from config at startup
//   - kid: the deterministic key ID (from keys.DeriveKID); embedded in the JOSE header
//   - subject: UUID string of the user or service account
//   - subjectType: "user" or "service_account"
//   - scopes: granted scopes — joined with spaces and embedded in the "scope" claim
//   - ttl: how long this token is valid for
//
// The jti claim is a fresh UUID v4 on every call, making each token uniquely
// identifiable for future introspection or revocation endpoints.
func MintAccessToken(key *rsa.PrivateKey, kid, subject, subjectType string, scopes []string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()

	// Build the claims. RegisteredClaims provides the standard JOSE fields.
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   Issuer,
			Subject:  subject,
			IssuedAt: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			// jti (JWT ID) is a UUID v4 unique to this specific token issuance.
			// It can be used by an introspection endpoint or audit log to
			// identify exactly which token was used in a request.
			ID: uuid.New().String(),
		},
		// Join scopes with a space — the OAuth 2.0 standard representation.
		// A JSON array would also work, but the space-separated format is what
		// RFC 6749 specifies and what most OAuth libraries expect.
		Scope:   scopeString(scopes),
		SubType: subjectType,
	}

	// Create the token object with the RS256 signing method.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Embed the key ID in the JOSE header so downstream verifiers can look up
	// the correct public key from the JWKS without trying every key.
	token.Header["kid"] = kid

	// Sign the token. This computes the RSA signature over the base64url-encoded
	// header.payload using the private key.
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

// ParseAccessToken verifies an RS256 JWT and returns its claims.
//
// This is used by the optional introspection endpoint and in tests.
// Downstream services do their own local validation using the JWKS — they do
// NOT call this function (they don't have the private key, only the public key).
//
// Returns an error if the signature is invalid, the token is expired, or
// the issuer does not match.
func ParseAccessToken(tokenStr string, pub *rsa.PublicKey) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		// The key func is called after the header is decoded. It receives the
		// parsed (but not yet verified) token and must return the key to use
		// for verification. We return the public key unconditionally because
		// we only have one signing key at a time.
		func(t *jwt.Token) (interface{}, error) {
			// Reject tokens that use a different signing algorithm.
			// Without this check, an attacker could submit a token signed with
			// "none" or HS256 (using the public key as the HMAC secret) and
			// bypass verification.
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return pub, nil
		},
		// Validate the issuer claim. Tokens from other issuers are rejected.
		jwt.WithIssuer(Issuer),
		// Validate exp and iat claims.
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// RefreshTokenPair holds the raw refresh token (returned to the client) and
// its hash (stored in Postgres).
type RefreshTokenPair struct {
	// Raw is the opaque token returned to the client.
	// It is a base64url-encoded 32-byte random value.
	// It is returned exactly once and never stored.
	Raw string

	// Hash is hex(SHA-256(raw_bytes_before_encoding)).
	// This is stored in the refresh_tokens table.
	Hash string
}

// GenerateRefreshToken creates a new refresh token pair.
//
// 32 bytes of crypto/rand provides 256 bits of entropy. This is enough to
// make brute-force guessing computationally infeasible even with access to
// the hash database.
//
// We hash the raw bytes (before base64 encoding) so the hash is stable
// regardless of the encoding used.
func GenerateRefreshToken() (*RefreshTokenPair, error) {
	// Read 32 bytes from the OS cryptographic random source.
	// crypto/rand reads from /dev/urandom on Linux and CryptGenRandom on Windows.
	// math/rand is NOT used here — it is seeded from a predictable source and
	// an attacker who can observe a few tokens could predict future ones.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate refresh token: read random bytes: %w", err)
	}

	// Hash the raw bytes with SHA-256. This is the value stored in Postgres.
	sum := sha256.Sum256(buf)
	hash := fmt.Sprintf("%x", sum)

	// Base64url-encode the raw bytes for the client. No padding (RawURLEncoding)
	// — padding characters (=) can cause issues in HTTP headers and query strings.
	raw := base64.RawURLEncoding.EncodeToString(buf)

	return &RefreshTokenPair{Raw: raw, Hash: hash}, nil
}

// HashRefreshToken computes the SHA-256 hash of a raw refresh token received
// from the client, for use in the Postgres lookup.
//
// The client sends the raw base64url-encoded token. We decode it back to
// bytes and hash those bytes — matching the hash stored at generation time.
func HashRefreshToken(raw string) (string, error) {
	buf, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("decode refresh token: %w", err)
	}
	sum := sha256.Sum256(buf)
	return fmt.Sprintf("%x", sum), nil
}

// scopeString joins a slice of scope strings into a single space-separated
// string as required by RFC 6749 §3.3.
func scopeString(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}
