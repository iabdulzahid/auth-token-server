// Package handler contains all HTTP handlers for the Auth Token Server.
package handler

import "net/http"

// JWKS handles GET /.well-known/jwks.json.
//
// The response is the pre-built JWKS document (h.JWKSPayload) containing the
// RSA public key. Built once at startup, served on every request with no
// per-request allocation.
//
// Cache-Control: public, max-age=3600 tells downstream services they may cache
// this response for 1 hour. The cache is invalidated on key rotation when the
// kid changes, causing a kid-miss on verification and a forced re-fetch.
//
// No authentication required — the public key is safe to expose.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.JWKSPayload)
}
