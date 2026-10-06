// revoke.go implements POST /auth/revoke.
//
// Explicit revocation allows a client to invalidate a refresh token before
// it expires — for example, on user logout or when a client detects a
// potential compromise.
//
// # Request (application/x-www-form-urlencoded)
//
//	refresh_token=<opaque base64url token>
//
// # Response
//
//   - 200 OK (empty body) — token was found and revoked, or was already revoked.
//     Idempotent: revoking an already-revoked token is not an error.
//   - 400 invalid_request — refresh_token field missing or malformed base64.
//   - 500 server_error    — unexpected internal failure.
//
// # Authority order
//
// Postgres is revoked FIRST. Only after the Postgres UPDATE succeeds do we
// write to Redis (best-effort). If Redis fails, the Postgres record is the
// authoritative revocation — future refresh attempts will fall through to
// Postgres and see revoked=true.
//
// We never return 401 for "token not found" on this endpoint. The OAuth 2.0
// revocation RFC (RFC 7009) specifies that the server SHOULD respond with
// 200 even if the token is unknown, to avoid leaking information about which
// tokens exist.
package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/iabdulzahid/auth-token-server/internal/store"
	"github.com/iabdulzahid/auth-token-server/internal/token"
)

// Revoke handles POST /auth/revoke.
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not parse request body")
		return
	}

	rawToken := r.PostFormValue("refresh_token")
	if rawToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	// Hash the raw token for the Postgres lookup.
	tokenHash, err := token.HashRefreshToken(rawToken)
	if err != nil {
		// Malformed base64 — cannot be a token we issued. Per RFC 7009 we still
		// return 400 because the request itself is malformed.
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid refresh_token format")
		return
	}

	// Look up the token row to get its ID and expiry (needed for Redis TTL).
	// We use GetByHash (no lock) — explicit revocation is a one-way operation
	// and does not need the TOCTOU protection of SELECT FOR UPDATE.
	rt, err := h.RefreshTokens.GetByHash(r.Context(), tokenHash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Per RFC 7009: treat unknown tokens as successfully revoked (200).
			w.WriteHeader(http.StatusOK)
			return
		}
		log.Error().Err(err).Msg("GetByHash on /revoke failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// If already revoked, nothing to do — return 200 (idempotent).
	if rt.Revoked {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Revoke in Postgres first. tx=nil means use the pool directly (no transaction
	// needed — revocation is a single UPDATE that is atomic on its own).
	if err := h.RefreshTokens.Revoke(r.Context(), nil, rt.ID); err != nil {
		log.Error().Err(err).Str("token_id", rt.ID.String()).Msg("Revoke in Postgres failed")
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	// Postgres revocation committed. Now respond 200 to the client.
	w.WriteHeader(http.StatusOK)

	// Best-effort: populate Redis so future refresh attempts on this token hit
	// the Redis fast-path instead of going to Postgres.
	ttl := time.Until(rt.ExpiresAt)
	if ttl < time.Second {
		ttl = time.Second // floor: don't pass a zero or negative TTL to Redis
	}
	h.Cache.SetRevoked(r.Context(), tokenHash, ttl)
}
