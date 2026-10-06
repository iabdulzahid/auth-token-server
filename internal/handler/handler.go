// handler.go defines shared types, helpers, and the dependency container used
// by all HTTP handlers in the ATS.
//
// # Handler design
//
// Each handler is a method on *Handler, which holds all injected dependencies:
// stores, cache, config values, and the pre-built RSA key + JWKS bytes.
// This avoids global state and makes handlers unit-testable with fakes.
//
// # Error responses
//
// All error responses follow the OAuth 2.0 error format (RFC 6749 §5.2):
//
//	{ "error": "<code>", "error_description": "<human text>" }
//
// HTTP status codes:
//   - 400 Bad Request     — malformed input, missing required fields, invalid grant_type
//   - 401 Unauthorized    — bad credentials, revoked/expired token
//   - 500 Internal Server — unexpected server-side failures
package handler

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"

	"github.com/jmoiron/sqlx"

	"github.com/iabdulzahid/auth-token-server/internal/cache"
	"github.com/iabdulzahid/auth-token-server/internal/store"
)

// Handler holds all dependencies injected at startup. All HTTP handler
// methods are defined on this struct.
type Handler struct {
	// Store repos
	Users           store.UserStore
	ServiceAccounts store.ServiceAccountStore
	RefreshTokens   store.RefreshTokenStore

	// DB is the raw sqlx pool, used by the Refresh handler to open transactions
	// for the SELECT FOR UPDATE rotation flow. We cannot open transactions through
	// the RefreshTokenStore interface alone because transactions span multiple
	// store calls (GetByHashForUpdate + Revoke + Insert must all be atomic).
	DB *sqlx.DB

	// Cache
	Cache *cache.Cache

	// RSA signing key and pre-built JWKS bytes (built once at startup).
	PrivateKey  *rsa.PrivateKey
	KID         string
	JWKSPayload []byte

	// Token TTLs from config
	AccessTokenTTL  int64 // seconds
	RefreshTokenTTL int64 // seconds

	// BcryptCost used when creating users/service accounts (informational — actual
	// hashing is done outside handlers, but stored here for completeness).
	BcryptCost int
}

// ---------------------------------------------------------------------------
// Shared response helpers
// ---------------------------------------------------------------------------

// errResponse is the OAuth 2.0 error envelope (RFC 6749 §5.2).
type errResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// tokenResponse is the successful token issuance envelope (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`   // always "Bearer"
	ExpiresIn    int64  `json:"expires_in"`   // seconds until access token expires
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// writeJSON serialises v as JSON and writes it to w with the given status code.
// Content-Type is always application/json.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// json.NewEncoder writes directly to the ResponseWriter without buffering
	// the full payload in memory first — efficient for large responses.
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes an OAuth 2.0 error response.
func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, errResponse{Error: code, Description: description})
}
