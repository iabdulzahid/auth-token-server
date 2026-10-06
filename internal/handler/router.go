// router.go wires all HTTP routes onto a chi.Router and attaches middleware.
//
// # Routes
//
//   POST  /auth/token           — issue access + refresh token pair
//   POST  /auth/refresh         — rotate refresh token, issue new access token
//   POST  /auth/revoke          — explicitly revoke a refresh token
//   GET   /.well-known/jwks.json — JWKS public key document
//   GET   /health               — liveness probe (always 200 if process is up)
//   GET   /ready                — readiness probe (checks Postgres + Redis)
//
// # Middleware
//
//   - Request logger: logs method, path, status code, and latency via zerolog.
//   - Recoverer: catches panics, logs them, and returns 500 instead of crashing.
package handler

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

// NewRouter builds and returns a chi.Router with all ATS routes registered.
func NewRouter(h *Handler) chi.Router {
	r := chi.NewRouter()

	// ---------------------------------------------------------------------------
	// Middleware stack (applied to every route)
	// ---------------------------------------------------------------------------

	// RealIP reads X-Forwarded-For / X-Real-IP headers and sets r.RemoteAddr.
	// Needed when ATS runs behind a reverse proxy or load balancer.
	r.Use(middleware.RealIP)

	// RequestLogger logs every request using zerolog. Chi's built-in logger
	// uses the standard library; we replace it with our own zerolog adapter.
	r.Use(zerologRequestLogger)

	// Recoverer catches panics in handlers, logs the stack trace, and returns
	// 500 to the client instead of crashing the server.
	r.Use(middleware.Recoverer)

	// ---------------------------------------------------------------------------
	// Auth routes
	// ---------------------------------------------------------------------------
	r.Post("/auth/token", h.Token)
	r.Post("/auth/refresh", h.Refresh)
	r.Post("/auth/revoke", h.Revoke)

	// ---------------------------------------------------------------------------
	// JWKS discovery endpoint
	// ---------------------------------------------------------------------------
	// Cache-Control: public, max-age=3600 tells downstream caches and services
	// they can cache this document for 1 hour without re-fetching. The document
	// only changes on key rotation, which is an intentional operator action.
	r.Get("/.well-known/jwks.json", h.JWKS)

	// ---------------------------------------------------------------------------
	// Health and readiness probes
	// ---------------------------------------------------------------------------
	r.Get("/health", h.Health)
	r.Get("/ready", h.Ready)

	return r
}

// zerologRequestLogger is a chi-compatible middleware that logs each request
// with method, path, status code, and latency using zerolog.
//
// We write our own instead of using chi's built-in Logger middleware because
// chi's logger uses log.Printf (stdlib) and we want all logs in zerolog's
// structured JSON format.
func zerologRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// chi's WrapResponseWriter captures the status code written by the handler.
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.Status()).
				Dur("latency_ms", time.Since(start)).
				Str("remote_addr", r.RemoteAddr).
				Msg("request")
		}()

		next.ServeHTTP(ww, r)
	})
}
