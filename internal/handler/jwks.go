// Package handler contains all HTTP handlers for the Auth Token Server.
package handler

import "net/http"

// JWKSHandler returns an HTTP handler that serves the JWKS (JSON Web Key Set) document.
//
// The JWKS document contains the RSA public key that downstream services use to
// verify JWT signatures locally — without making a network call to ATS on every request.
//
// The jwksJSON parameter is a pre-built, immutable byte slice produced at startup by
// keys.BuildJWKS(). It is built once and reused on every request — no per-request
// allocation, no repeated marshalling.
//
// Downstream services should:
//  1. Fetch this endpoint once at startup.
//  2. Cache the result in memory, indexed by kid.
//  3. On a kid cache miss (new key rotation), re-fetch this endpoint.
//
// This endpoint requires no authentication — the public key is safe to expose.
func JWKSHandler(jwksJSON []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Cache-Control: downstream services may cache the JWKS for up to 1 hour.
		// This reduces load on ATS while still allowing key rotation to propagate
		// within a reasonable time window.
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwksJSON)
	}
}
