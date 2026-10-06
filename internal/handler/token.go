// token.go implements POST /auth/token.
//
// Supported grant types (distinguished by the "grant_type" form field):
//
//   - "password"           — human user authenticates with email + password
//   - "client_credentials" — M2M service authenticates with client_id + client_secret
//
// # Request format (application/x-www-form-urlencoded)
//
// Password grant:
//
//	grant_type=password&username=alice@example.com&password=secret&scope=read:orders
//
// Client credentials grant:
//
//	grant_type=client_credentials&client_id=billing-svc&client_secret=s3cr3t&scope=read:orders
//
// # Response (200 OK)
//
//	{
//	  "access_token":  "<RS256 JWT>",
//	  "token_type":    "Bearer",
//	  "expires_in":    900,
//	  "refresh_token": "<opaque base64url>",
//	  "scope":         "read:orders"
//	}
//
// # Error responses
//
//   - 400 unsupported_grant_type  — grant_type missing or not recognised
//   - 400 invalid_request         — required fields missing
//   - 401 invalid_client          — client_id not found or secret wrong (client credentials)
//   - 401 invalid_grant           — email not found, password wrong, or account disabled (password)
//   - 500 server_error            — unexpected internal failure
package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/iabdulzahid/auth-token-server/internal/store"
	"github.com/iabdulzahid/auth-token-server/internal/token"
)

// Token handles POST /auth/token.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	// ParseForm populates r.PostForm from the request body.
	// We require application/x-www-form-urlencoded (the standard for OAuth token
	// endpoints) — not JSON — so that the ATS is compatible with OAuth clients
	// and libraries out of the box.
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not parse request body")
		return
	}

	grantType := r.PostFormValue("grant_type")
	switch grantType {
	case "password":
		h.handlePasswordGrant(w, r)
	case "client_credentials":
		h.handleClientCredentialsGrant(w, r)
	case "":
		writeError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			"supported grant types: password, client_credentials")
	}
}

// handlePasswordGrant authenticates a human user with email + password and
// issues an access token + refresh token pair.
func (h *Handler) handlePasswordGrant(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	scopeStr := strings.TrimSpace(r.PostFormValue("scope"))

	if email == "" || password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"username and password are required for password grant")
		return
	}

	// Look up the user. We return the same error for "not found" and "wrong
	// password" to avoid leaking whether an email exists (user enumeration).
	user, err := h.Users.GetByEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Perform a dummy bcrypt comparison to keep constant response time.
			// Without this, an attacker could time the response to detect whether
			// an email exists: a miss returns instantly, a hit takes bcrypt time.
			_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummy"), []byte(password))
			writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
			return
		}
		log.Error().Err(err).Str("email", email).Msg("GetByEmail failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	if user.Disabled {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "account is disabled")
		return
	}

	// Verify the password against the stored bcrypt hash.
	// bcrypt.CompareHashAndPassword returns bcrypt.ErrMismatchedHashAndPassword
	// on a wrong password and nil on a match.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return
	}

	// Intersect the requested scopes with the user's allowed scopes.
	// A user can only receive scopes they have been granted — they cannot
	// escalate by requesting a scope they don't own.
	granted := intersectScopes(parseScopes(scopeStr), user.ScopesAsStrings())

	h.issueTokenPair(w, r, user.ID.String(), "user", granted)
}

// handleClientCredentialsGrant authenticates a service account with
// client_id + client_secret and issues an access token + refresh token pair.
func (h *Handler) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.PostFormValue("client_id"))
	clientSecret := r.PostFormValue("client_secret")
	scopeStr := strings.TrimSpace(r.PostFormValue("scope"))

	if clientID == "" || clientSecret == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"client_id and client_secret are required for client_credentials grant")
		return
	}

	sa, err := h.ServiceAccounts.GetByClientID(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummy"), []byte(clientSecret))
			writeError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
			return
		}
		log.Error().Err(err).Str("client_id", clientID).Msg("GetByClientID failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	if sa.Disabled {
		writeError(w, http.StatusUnauthorized, "invalid_client", "client is disabled")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(sa.ClientSecretHash), []byte(clientSecret)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	granted := intersectScopes(parseScopes(scopeStr), sa.ScopesAsStrings())

	h.issueTokenPair(w, r, sa.ID.String(), "service_account", granted)
}

// issueTokenPair mints an access token + refresh token and writes the token
// response. Shared by both grant paths.
func (h *Handler) issueTokenPair(w http.ResponseWriter, r *http.Request, subject, subjectType string, scopes []string) {
	// Mint the RS256 JWT access token.
	accessTTL := time.Duration(h.AccessTokenTTL) * time.Second
	accessToken, err := token.MintAccessToken(h.PrivateKey, h.KID, subject, subjectType, scopes, accessTTL)
	if err != nil {
		log.Error().Err(err).Msg("MintAccessToken failed")
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}

	// Generate the opaque refresh token (32 bytes, crypto/rand).
	rtPair, err := token.GenerateRefreshToken()
	if err != nil {
		log.Error().Err(err).Msg("GenerateRefreshToken failed")
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}

	// Parse subject UUID for the store row.
	subjectUUID, err := uuid.Parse(subject)
	if err != nil {
		log.Error().Err(err).Str("subject", subject).Msg("invalid subject UUID")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	now := time.Now().UTC()
	refreshTTL := time.Duration(h.RefreshTokenTTL) * time.Second

	// Persist the refresh token hash to Postgres.
	rt := &store.RefreshToken{
		ID:          uuid.New(),
		TokenHash:   rtPair.Hash,
		Subject:     subjectUUID,
		SubjectType: subjectType,
		Scopes:      store.NewStringArray(scopes),
		IssuedAt:    now,
		ExpiresAt:   now.Add(refreshTTL),
	}
	if err := h.RefreshTokens.Insert(r.Context(), rt); err != nil {
		log.Error().Err(err).Msg("Insert refresh token failed")
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.AccessTokenTTL,
		RefreshToken: rtPair.Raw,
		Scope:        joinScopes(scopes),
	})
}

// ---------------------------------------------------------------------------
// Scope helpers
// ---------------------------------------------------------------------------

// parseScopes splits a space-separated scope string into a deduplicated slice.
func parseScopes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Fields(s) // Fields splits on any whitespace and ignores leading/trailing
	seen := make(map[string]bool, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// intersectScopes returns scopes that appear in both requested and allowed.
// If requested is nil/empty, all allowed scopes are returned (the client is
// asking for "whatever you'll give me").
func intersectScopes(requested, allowed []string) []string {
	if len(requested) == 0 {
		return allowed
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = true
	}
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if allowedSet[s] {
			out = append(out, s)
		}
	}
	return out
}

// joinScopes joins a scope slice into a space-separated string for the response.
func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}
