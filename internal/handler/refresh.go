// refresh.go implements POST /auth/refresh.
//
// This is the most security-critical endpoint in the ATS because it implements
// token rotation with a SELECT FOR UPDATE lock to prevent TOCTOU races.
//
// # Request (application/x-www-form-urlencoded)
//
//	refresh_token=<opaque base64url token>
//
// # Response (200 OK) — same shape as /auth/token
//
//	{
//	  "access_token":  "<new RS256 JWT>",
//	  "token_type":    "Bearer",
//	  "expires_in":    900,
//	  "refresh_token": "<new opaque token>",
//	  "scope":         "read:orders"
//	}
//
// # Full rotation flow
//
//  1. Check Redis fast-path: if the token hash is already revoked in Redis → 401 immediately.
//  2. Hash the raw token from the request (SHA-256).
//  3. BEGIN Postgres transaction.
//  4. SELECT ... FOR UPDATE — acquires a row-level lock.
//     If a second request comes in with the same token concurrently, it blocks here
//     until this transaction completes, then sees revoked=true and returns 401.
//  5. Validate the locked row: exists, not revoked, not expired.
//  6. UPDATE old row: revoked=true, revoked_at=NOW().
//  7. INSERT new refresh token row.
//  8. COMMIT.
//  9. Mint new access token + return response.
//  10. SetRevoked in Redis (best-effort, after response is written — non-blocking).
//
// # Error responses
//
//   - 400 invalid_request  — refresh_token field missing
//   - 401 invalid_grant    — token not found, revoked, or expired
//   - 500 server_error     — unexpected internal failure
package handler

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/iabdulzahid/auth-token-server/internal/store"
	"github.com/iabdulzahid/auth-token-server/internal/token"
)

// Refresh handles POST /auth/refresh.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not parse request body")
		return
	}

	rawToken := r.PostFormValue("refresh_token")
	if rawToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	// Step 1: hash the raw token — this is what's stored in Postgres and Redis.
	tokenHash, err := token.HashRefreshToken(rawToken)
	if err != nil {
		// Invalid base64 — the token cannot possibly be valid.
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid refresh token")
		return
	}

	// Step 2: Redis fast-path revocation check.
	// If Redis says the token is revoked, reject immediately without hitting Postgres.
	// This is the only scenario where we trust Redis as the sole decision maker —
	// a positive revocation entry is reliable because we write it ourselves.
	revoked, ok, redisErr := h.Cache.IsRevoked(r.Context(), tokenHash)
	if redisErr == nil && ok && revoked {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "refresh token has been revoked")
		return
	}
	// On Redis miss (ok=false) or Redis error — fall through to Postgres.
	// Log Redis errors for monitoring but do not surface them to the client.
	if redisErr != nil {
		log.Warn().Err(redisErr).Msg("Redis IsRevoked error on /refresh; falling through to Postgres")
	}

	// Step 3: open a Postgres transaction for the rotation.
	// h.DB is the shared *sqlx.DB pool injected at startup. We use it directly
	// here because the rotation requires multiple store operations (lock, revoke,
	// insert) to run atomically inside one transaction — the store interface
	// methods accept a *sql.Tx, so we open the tx here and pass it through.
	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		log.Error().Err(err).Msg("begin transaction for token rotation")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	defer tx.Rollback() //nolint:errcheck — Rollback is a no-op after Commit

	// Step 4: SELECT FOR UPDATE — lock the row.
	// Any concurrent request with the same token will block here until we commit.
	rt, err := h.RefreshTokens.GetByHashForUpdate(r.Context(), tx, tokenHash)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusUnauthorized, "invalid_grant", "refresh token not found")
			return
		}
		log.Error().Err(err).Msg("GetByHashForUpdate failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Step 5: validate the locked row.
	if rt.Revoked {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "refresh token has been revoked")
		return
	}
	if rt.IsExpired() {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "refresh token has expired")
		return
	}

	// Step 6: revoke the old token inside the transaction.
	if err := h.RefreshTokens.Revoke(r.Context(), tx, rt.ID); err != nil {
		log.Error().Err(err).Str("token_id", rt.ID.String()).Msg("Revoke old token failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Step 7: generate and insert the new refresh token inside the same transaction.
	newRTPair, err := token.GenerateRefreshToken()
	if err != nil {
		log.Error().Err(err).Msg("GenerateRefreshToken failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	now := time.Now().UTC()
	refreshTTL := time.Duration(h.RefreshTokenTTL) * time.Second
	newRT := &store.RefreshToken{
		ID:          uuid.New(),
		TokenHash:   newRTPair.Hash,
		Subject:     rt.Subject,
		SubjectType: rt.SubjectType,
		Scopes:      rt.Scopes,
		IssuedAt:    now,
		ExpiresAt:   now.Add(refreshTTL),
	}
	if err := h.RefreshTokens.Insert(r.Context(), newRT); err != nil {
		log.Error().Err(err).Msg("Insert new refresh token failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Step 8: commit — old token revoked + new token inserted atomically.
	if err := tx.Commit(); err != nil {
		log.Error().Err(err).Msg("commit token rotation transaction failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Step 9: mint the new access token.
	accessTTL := time.Duration(h.AccessTokenTTL) * time.Second
	accessToken, err := token.MintAccessToken(
		h.PrivateKey, h.KID,
		rt.Subject.String(), rt.SubjectType,
		rt.ScopesAsStrings(),
		accessTTL,
	)
	if err != nil {
		// The rotation is already committed to Postgres. We cannot un-rotate.
		// Log the error — the client will retry with the new refresh token.
		log.Error().Err(err).Msg("MintAccessToken failed after rotation commit")
		writeError(w, http.StatusInternalServerError, "server_error", "could not mint access token")
		return
	}

	// Write the response before the Redis update so a slow Redis cannot delay
	// the HTTP response to the client.
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.AccessTokenTTL,
		RefreshToken: newRTPair.Raw,
		Scope:        joinScopes(rt.ScopesAsStrings()),
	})

	// Step 10: populate Redis with the old token's revocation (best-effort).
	// This runs after the response is written. If it fails, the Postgres record
	// is still correct — future requests will fall through to Postgres.
	// TTL is the remaining lifetime of the OLD token (already past ExpiresAt
	// in most cases, but we use a floor of 1 second to avoid a zero TTL).
	oldTTL := time.Until(rt.ExpiresAt)
	if oldTTL < time.Second {
		oldTTL = time.Second
	}
	h.Cache.SetRevoked(r.Context(), tokenHash, oldTTL)
}

// isNotFound returns true if the error represents a "row not found" condition.
func isNotFound(err error) bool {
	return err == store.ErrNotFound
}
