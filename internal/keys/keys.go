// Package keys handles RSA private key loading and JWKS (JSON Web Key Set) generation.
//
// # Responsibilities
//
// 1. Parse an RSA private key from a PEM-encoded string (loaded from config).
// 2. Derive a stable Key ID (kid) from the public key using a SHA-256 thumbprint.
// 3. Build a JWKS document (RFC 7517) from the public key so downstream services
//    can verify JWTs locally without calling ATS on every request.
//
// # Why a deterministic kid?
//
// The kid is embedded in every JWT header and must match an entry in the JWKS.
// If kid were randomly generated at startup:
//   - Each ATS replica would have a different kid.
//   - After a restart, the kid changes — JWTs issued before the restart carry
//     the old kid, which no longer appears in the JWKS.
//   - Downstream services would fail to find the key and reject all in-flight tokens.
//
// By deriving kid from SHA-256(public key), the same key always produces the same kid —
// across restarts, across replicas, across deployments. Only a key change changes the kid.
//
// # Key generation (one-time, outside the application)
//
//	openssl genrsa -out private.pem 2048
//	export RSA_PRIVATE_KEY_PEM=$(cat private.pem)
//
// # RFC references
//
//   - RFC 7517: JSON Web Key (JWK)
//   - RFC 7638: JSON Web Key (JWK) Thumbprint
package keys

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
)

// JWK represents a single JSON Web Key as defined by RFC 7517.
// Only the fields required for RSA signature verification are included.
type JWK struct {
	// Kty is the key type. Always "RSA" for RSA keys.
	Kty string `json:"kty"`

	// Use indicates the intended use of the key.
	// "sig" means the key is used for signing and verification.
	Use string `json:"use"`

	// Alg is the algorithm this key is intended for.
	// "RS256" means RSA with SHA-256.
	Alg string `json:"alg"`

	// Kid is the Key ID — a stable identifier for this specific key.
	// Derived as hex(SHA-256(public key thumbprint)) so it is deterministic.
	Kid string `json:"kid"`

	// N is the base64url-encoded RSA modulus.
	// Together with E, it fully describes the RSA public key.
	N string `json:"n"`

	// E is the base64url-encoded RSA public exponent.
	// For 2048-bit RSA keys this is almost always 65537, encoded as "AQAB".
	E string `json:"e"`
}

// JWKS is the JSON Web Key Set envelope as defined by RFC 7517.
// It wraps one or more JWK entries. Downstream services fetch this document
// once at startup, cache it, and use it to verify JWTs locally.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ParsePrivateKey decodes and parses an RSA private key from a PEM-encoded string.
//
// Accepts both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") PEM formats.
// PKCS#1 is the format produced by `openssl genrsa`. PKCS#8 is used by some
// key management systems and cloud providers.
//
// Returns an error if the PEM block is missing, malformed, or not an RSA key.
// This error is fatal at startup — ATS cannot issue tokens without a signing key.
func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	// pem.Decode extracts the first PEM block from the string.
	// The second return value (rest) contains any remaining bytes after the block —
	// we ignore it because we only expect one key.
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block: no PEM data found in RSA_PRIVATE_KEY_PEM")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 format — produced by `openssl genrsa`
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 RSA private key: %w", err)
		}
		return key, nil

	case "PRIVATE KEY":
		// PKCS#8 format — used by some cloud KMS systems
		raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		key, ok := raw.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not an RSA key (got %T)", raw)
		}
		return key, nil

	default:
		return nil, fmt.Errorf("unsupported PEM block type %q: expected \"RSA PRIVATE KEY\" or \"PRIVATE KEY\"", block.Type)
	}
}

// DeriveKID computes a stable Key ID from an RSA public key.
//
// The kid is derived as:
//
//	hex( SHA-256( base64url(N) + "." + base64url(E) ) )
//
// where N and E are the base64url-encoded RSA modulus and exponent.
// This produces a deterministic, collision-resistant identifier that is
// identical across restarts and replicas as long as the key is the same.
//
// This is inspired by the JWK Thumbprint algorithm defined in RFC 7638,
// simplified to use hex encoding (instead of base64url) for readability
// in logs and debug output.
func DeriveKID(pub *rsa.PublicKey) string {
	// Encode the modulus and exponent in the same way they appear in the JWKS.
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	// Hash the concatenation to produce a fixed-length, unique identifier.
	h := sha256.Sum256([]byte(n + "." + e))

	// Return as a hex string — easy to read in logs and match against JWT headers.
	return fmt.Sprintf("%x", h)
}

// BuildJWKS constructs a JWKS document from an RSA public key and its kid.
//
// The returned []byte is a JSON-encoded JWKS that can be served directly
// at GET /.well-known/jwks.json with Content-Type: application/json.
//
// The document is built once at startup and cached in memory — there is no
// need to rebuild it on every request since the key never changes at runtime.
func BuildJWKS(pub *rsa.PublicKey, kid string) ([]byte, error) {
	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: kid,
				// N is the RSA modulus — the large prime product that is the public key.
				// base64url encoding (no padding) is the standard representation in JWK.
				N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				// E is the public exponent. For 2048-bit RSA keys this is 65537.
				// big.Int encoding followed by base64url gives the standard "AQAB".
				E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}

	data, err := json.Marshal(jwks)
	if err != nil {
		// json.Marshal on a struct with only string fields cannot fail in practice,
		// but we propagate the error for correctness.
		return nil, fmt.Errorf("failed to marshal JWKS: %w", err)
	}
	return data, nil
}
