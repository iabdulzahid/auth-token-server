// health.go implements the /health and /ready probes.
//
// # /health — liveness
//
// Returns 200 if the process is running. No dependency checks. Kubernetes uses
// this to decide whether to restart the pod. A dead process cannot respond, so
// a 200 here means "I am alive."
//
// # /ready — readiness
//
// Returns 200 only if both Postgres and Redis are reachable. Kubernetes uses
// this to decide whether to send traffic to this pod. A pod that is alive but
// cannot reach its dependencies should be taken out of rotation until it recovers.
//
// Redis failure returns 200 with a warning in the body — Redis is optional
// (the system degrades gracefully without it). Postgres failure returns 503
// because the ATS cannot serve any token operations without its database.
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// healthBody is the JSON body returned by /health and /ready.
type healthBody struct {
	Status   string            `json:"status"`
	Checks   map[string]string `json:"checks,omitempty"`
}

// Health handles GET /health — liveness probe.
// Always returns 200 {"status":"ok"} if the process can handle requests.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthBody{Status: "ok"})
}

// Ready handles GET /ready — readiness probe.
// Returns 200 if both Postgres and Redis dependencies are reachable.
// Returns 503 if Postgres is down (ATS cannot function without the database).
// Returns 200 with a warning if only Redis is down (degraded but functional).
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	// Use a short timeout so a hung dependency doesn't block the probe.
	// Kubernetes default probe timeout is 1 second; we use 2 to give slightly
	// more room while still failing fast.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := make(map[string]string, 2)

	// Check Postgres.
	if err := h.DB.PingContext(ctx); err != nil {
		checks["postgres"] = "unhealthy: " + err.Error()
		// Postgres down = not ready. Return 503 immediately.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(healthBody{Status: "not ready", Checks: checks})
		return
	}
	checks["postgres"] = "ok"

	// Check Redis (best-effort — Redis down ≠ not ready).
	if err := h.Cache.Ping(ctx); err != nil {
		// Redis is down but the service can still function using Postgres fallback.
		// Log the degraded state but return 200 — don't reject traffic.
		checks["redis"] = "degraded: " + err.Error()
	} else {
		checks["redis"] = "ok"
	}

	writeJSON(w, http.StatusOK, healthBody{Status: "ok", Checks: checks})
}
