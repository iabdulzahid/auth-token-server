// Package config loads and validates all runtime configuration from environment variables.
//
// # Design Decisions
//
// ## Why environment variables?
// The 12-Factor App methodology (https://12factor.net/config) states that configuration
// which differs between deployments (dev/staging/production) must live in the environment —
// never hardcoded or committed to git. This means the same Docker image is deployable
// in any environment: only the injected env vars change, not the binary.
//
// In Kubernetes:
//   - Non-sensitive values (SERVER_ADDR, ACCESS_TOKEN_TTL) → ConfigMap
//   - Sensitive values (DATABASE_DSN, RSA_PRIVATE_KEY_PEM) → Secret
//
// Both are injected as environment variables at runtime.
//
// ## Why collect ALL missing errors instead of failing on the first?
// In production, a missing config causes a failed deployment. If Load() returned on the
// first missing variable, an operator would need one deploy cycle per missing variable
// to discover them all. Collecting every error upfront means one fix-and-redeploy cycle
// fixes everything at once.
//
// ## Why no os.Getenv calls outside this package?
// Centralising all env reads here means there is exactly one place to look when debugging
// a config issue. If os.Getenv were scattered across packages, you would need to grep the
// entire codebase to understand what the service expects from its environment.
// Dependency injection (passing *Config everywhere) also makes testing trivial — just
// construct a Config struct in the test, no env var setup needed.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration for ATS.
// Every field is populated from an environment variable — nothing is hardcoded.
// All other packages receive *Config by dependency injection.
//
// See .env.example for the full list of environment variables with descriptions.
type Config struct {
	// DSN is the PostgreSQL connection string.
	// Format: postgres://user:password@host:port/dbname?sslmode=disable
	//
	// PostgreSQL is the durable source of truth for all token and identity data.
	// ATS cannot function without a database — missing DSN is a fatal startup error.
	//
	// Environment variable: DATABASE_DSN
	// Required: yes
	DSN string

	// RedisAddr is the Redis server address in host:port format.
	// Example: localhost:6379
	//
	// Redis is used exclusively as a write-through revocation cache.
	// If Redis is unavailable at startup, ATS logs a warning and continues —
	// all revocation checks fall back to PostgreSQL automatically.
	//
	// Environment variable: REDIS_ADDR
	// Required: yes
	RedisAddr string

	// RedisPassword is the Redis AUTH password.
	// Leave empty if Redis has no password configured (common in local development).
	//
	// Environment variable: REDIS_PASSWORD
	// Required: no — defaults to empty string
	RedisPassword string

	// RSAPrivateKeyPEM is the PEM-encoded RSA private key used to sign JWT access tokens.
	//
	// Inject as a newline-preserved string. The easiest way to generate and export:
	//   openssl genrsa -out private.pem 2048
	//   export RSA_PRIVATE_KEY_PEM=$(cat private.pem)
	//
	// Why RSA (asymmetric) instead of HMAC (symmetric)?
	// With HMAC, every service that validates tokens needs the shared secret —
	// a single compromised service leaks the signing key. With RSA, downstream
	// services only need the public key (served via JWKS) and can never forge tokens.
	//
	// NEVER commit this value to git. Rotate by deploying a new key pair.
	//
	// Environment variable: RSA_PRIVATE_KEY_PEM
	// Required: yes
	RSAPrivateKeyPEM string

	// AccessTokenTTL is the lifetime of issued JWT access tokens.
	//
	// Short TTL limits the blast radius of a stolen token — the attacker's window
	// is at most AccessTokenTTL before the token becomes useless without a refresh.
	// Trade-off: shorter TTL → more /auth/refresh calls → higher load on ATS.
	// 15 minutes is the industry standard balance.
	//
	// Environment variable: ACCESS_TOKEN_TTL (Go duration string, e.g. "15m")
	// Required: no — defaults to 15m
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the lifetime of issued refresh tokens.
	//
	// After this duration, the refresh token record expires in PostgreSQL and
	// the user must authenticate again with credentials. Longer TTL improves UX
	// (users stay logged in longer); shorter TTL improves security.
	// 7 days is a common balance for most applications.
	//
	// Environment variable: REFRESH_TOKEN_TTL (Go duration string, e.g. "168h")
	// Required: no — defaults to 168h (7 days)
	RefreshTokenTTL time.Duration

	// ServerAddr is the TCP address the HTTP server listens on.
	// Format: :port (e.g. :8080) or host:port (e.g. 0.0.0.0:8080)
	//
	// Environment variable: SERVER_ADDR
	// Required: no — defaults to :8080
	ServerAddr string

	// BcryptCost is the bcrypt work factor used when hashing passwords and client secrets.
	//
	// Higher cost = more CPU time per hash = harder to brute-force offline.
	// Each increment of 1 doubles the computation time.
	// Cost 12 takes ~250ms on modern hardware — acceptable for login, too slow for
	// hot paths. Never use below 10 (bcrypt.MinCost).
	//
	// Environment variable: BCRYPT_COST
	// Required: no — defaults to 12
	BcryptCost int
}

// Load reads all configuration from environment variables, applies defaults for
// optional fields, and validates that all required fields are present and parseable.
//
// All errors are collected before returning, so an operator learns about every
// misconfiguration in a single startup failure rather than one at a time.
//
// Returns a fully populated *Config on success.
// Returns an error listing every problem on failure — the service must not start.
func Load() (*Config, error) {
	var errs []string

	// required reads a required environment variable.
	// If the variable is absent or blank, the name is recorded in errs.
	// The empty string returned is never used in a running service — Load()
	// will return an error before the Config reaches any caller.
	required := func(key string) string {
		val := os.Getenv(key)
		if strings.TrimSpace(val) == "" {
			errs = append(errs, fmt.Sprintf("%s is required but not set", key))
		}
		return val
	}

	// optional reads an environment variable and falls back to the provided
	// default value when the variable is absent or empty.
	optional := func(key, defaultVal string) string {
		if val := os.Getenv(key); strings.TrimSpace(val) != "" {
			return val
		}
		return defaultVal
	}

	// parseDuration parses a Go duration string (e.g. "15m", "168h").
	// An invalid string is recorded in errs rather than panicking.
	parseDuration := func(key, raw string) time.Duration {
		d, err := time.ParseDuration(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s has invalid duration %q: %v", key, raw, err))
			return 0
		}
		if d <= 0 {
			errs = append(errs, fmt.Sprintf("%s must be a positive duration, got %q", key, raw))
			return 0
		}
		return d
	}

	// parseInt parses an integer string.
	// An invalid string is recorded in errs.
	parseInt := func(key, raw string, min, max int) int {
		n, err := strconv.Atoi(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s has invalid integer %q: %v", key, raw, err))
			return 0
		}
		if n < min || n > max {
			errs = append(errs, fmt.Sprintf("%s must be between %d and %d, got %d", key, min, max, n))
			return 0
		}
		return n
	}

	// ── Required ──────────────────────────────────────────────────────────────
	dsn              := required("DATABASE_DSN")
	redisAddr        := required("REDIS_ADDR")
	rsaPrivateKeyPEM := required("RSA_PRIVATE_KEY_PEM")

	// ── Optional with defaults ────────────────────────────────────────────────
	redisPassword      := os.Getenv("REDIS_PASSWORD") // empty string is a valid value
	accessTokenTTLRaw  := optional("ACCESS_TOKEN_TTL", "15m")
	refreshTokenTTLRaw := optional("REFRESH_TOKEN_TTL", "168h")
	serverAddr         := optional("SERVER_ADDR", ":8080")
	bcryptCostRaw      := optional("BCRYPT_COST", "12")

	// ── Parse and validate ────────────────────────────────────────────────────
	accessTokenTTL  := parseDuration("ACCESS_TOKEN_TTL", accessTokenTTLRaw)
	refreshTokenTTL := parseDuration("REFRESH_TOKEN_TTL", refreshTokenTTLRaw)

	// bcrypt cost: Go's bcrypt package accepts 4–31. Below 10 is insecure.
	// We enforce a minimum of 10 and a maximum of 31.
	bcryptCost := parseInt("BCRYPT_COST", bcryptCostRaw, 10, 31)

	// ── Return all errors at once ─────────────────────────────────────────────
	if len(errs) > 0 {
		return nil, fmt.Errorf("ATS configuration errors (%d):\n  • %s",
			len(errs), strings.Join(errs, "\n  • "))
	}

	return &Config{
		DSN:              dsn,
		RedisAddr:        redisAddr,
		RedisPassword:    redisPassword,
		RSAPrivateKeyPEM: rsaPrivateKeyPEM,
		AccessTokenTTL:   accessTokenTTL,
		RefreshTokenTTL:  refreshTokenTTL,
		ServerAddr:       serverAddr,
		BcryptCost:       bcryptCost,
	}, nil
}
