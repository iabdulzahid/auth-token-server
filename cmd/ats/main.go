package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver with database/sql
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/iabdulzahid/auth-token-server/internal/cache"
	"github.com/iabdulzahid/auth-token-server/internal/config"
	"github.com/iabdulzahid/auth-token-server/internal/handler"
	"github.com/iabdulzahid/auth-token-server/internal/keys"
	"github.com/iabdulzahid/auth-token-server/internal/store"
)

// Version and GitSHA are injected at build time via -ldflags:
//
//	go build -ldflags="-X main.Version=v1.2.3 -X main.GitSHA=abc1234" ./cmd/ats
//
// In development (no ldflags), they default to "dev" and "unknown".
var (
	Version = "dev"
	GitSHA  = "unknown"
)

func main() {
	// ---------------------------------------------------------------------------
	// 1. Configure zerolog — structured JSON logging on stdout.
	//
	// Why JSON? Log aggregators (Datadog, CloudWatch, Loki) parse JSON natively.
	// Structured logs can be filtered, grouped, and alerted on by field value
	// (e.g. all logs where status=500). Plain text requires fragile regex parsing.
	// ---------------------------------------------------------------------------
	log.Logger = zerolog.New(os.Stdout).With().
		Timestamp().
		Str("version", Version).
		Str("git_sha", GitSHA).
		Logger()

	log.Info().
		Str("go_version", runtime.Version()).
		Str("os", runtime.GOOS).
		Msg("ATS starting")

	// ---------------------------------------------------------------------------
	// 2. Load configuration from environment variables.
	//
	// config.Load() is the ONLY place os.Getenv is called. All other packages
	// receive a *Config by injection. This makes tests trivial — no env setup needed.
	// Fatal on any misconfiguration: better to crash early with a clear message
	// than to start in a broken state and fail later on the first request.
	// ---------------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("configuration error — fix env vars and restart")
	}
	log.Info().
		Str("server_addr", cfg.ServerAddr).
		Dur("access_ttl", cfg.AccessTokenTTL).
		Dur("refresh_ttl", cfg.RefreshTokenTTL).
		Int("bcrypt_cost", cfg.BcryptCost).
		Msg("configuration loaded")

	// ---------------------------------------------------------------------------
	// 3. Parse the RSA private key.
	//
	// The key is PEM-encoded and injected as an env var (RSA_PRIVATE_KEY_PEM).
	// We parse it once at startup, not per request. Parsing is expensive (ASN.1
	// decoding); once parsed, the *rsa.PrivateKey is used for all token signing.
	// Fatal on failure: a missing or malformed key means we cannot issue tokens.
	// ---------------------------------------------------------------------------
	privKey, err := keys.ParsePrivateKey(cfg.RSAPrivateKeyPEM)
	if err != nil {
		log.Fatal().Err(err).Msg("RSA private key parse error")
	}
	kid := keys.DeriveKID(&privKey.PublicKey)
	log.Info().Str("kid", kid).Msg("RSA key loaded")

	// ---------------------------------------------------------------------------
	// 4. Build the JWKS document (once, cached in memory).
	//
	// BuildJWKS constructs the JSON bytes. They are served on every
	// GET /.well-known/jwks.json request without re-marshalling.
	// ---------------------------------------------------------------------------
	jwksPayload, err := keys.BuildJWKS(&privKey.PublicKey, kid)
	if err != nil {
		log.Fatal().Err(err).Msg("JWKS build error")
	}

	// ---------------------------------------------------------------------------
	// 5. Connect to PostgreSQL.
	//
	// sqlx.Connect opens the connection pool AND pings the database.
	// Fatal on failure: Postgres is the source of truth; we cannot operate without it.
	// We use the "pgx" driver name, registered by the blank import above.
	// ---------------------------------------------------------------------------
	db, err := sqlx.Connect("pgx", cfg.DSN)
	if err != nil {
		log.Fatal().Err(err).Msg("PostgreSQL connection failed")
	}
	defer db.Close()

	// Tune the connection pool.
	// MaxOpenConns: prevents the pool from exhausting Postgres connection limits.
	// MaxIdleConns: keep a few connections warm to avoid reconnect latency.
	// ConnMaxLifetime: rotate connections to work around network middlebox limits.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	log.Info().Str("dsn", maskDSN(cfg.DSN)).Msg("PostgreSQL connected")

	// ---------------------------------------------------------------------------
	// 6. Run database migrations.
	//
	// Migrations are plain SQL files in migrations/. RunMigrations applies any
	// that haven't been applied yet (tracked in schema_migrations table).
	// Fatal on failure: a migration error means the schema is in an unknown state.
	// ---------------------------------------------------------------------------
	migrationsDir := migrationsPath()
	if err := store.RunMigrations(db, migrationsDir); err != nil {
		log.Fatal().Err(err).Str("dir", migrationsDir).Msg("migration failed")
	}
	log.Info().Str("dir", migrationsDir).Msg("migrations applied")

	// ---------------------------------------------------------------------------
	// 7. Connect to Redis.
	//
	// NewCache opens the connection and pings Redis. Unlike Postgres, a Redis
	// failure is NOT fatal — the ATS degrades gracefully to Postgres-only mode.
	// NewCache logs a warning internally on ping failure.
	// ---------------------------------------------------------------------------
	redisCache := cache.NewCache(cfg.RedisAddr, cfg.RedisPassword)

	// ---------------------------------------------------------------------------
	// 8. Build handler dependencies and router.
	// ---------------------------------------------------------------------------
	h := &handler.Handler{
		Users:           store.NewUserRepo(db),
		ServiceAccounts: store.NewServiceAccountRepo(db),
		RefreshTokens:   store.NewRefreshTokenRepo(db),
		DB:              db,
		Cache:           redisCache,
		PrivateKey:      privKey,
		KID:             kid,
		JWKSPayload:     jwksPayload,
		AccessTokenTTL:  int64(cfg.AccessTokenTTL.Seconds()),
		RefreshTokenTTL: int64(cfg.RefreshTokenTTL.Seconds()),
		BcryptCost:      cfg.BcryptCost,
	}

	router := handler.NewRouter(h)

	// ---------------------------------------------------------------------------
	// 9. Start the HTTP server.
	//
	// The server runs in a goroutine. The main goroutine blocks on a signal channel,
	// waiting for SIGTERM (Kubernetes pod shutdown) or SIGINT (Ctrl+C in dev).
	// On signal, we call server.Shutdown with a 10-second drain timeout to allow
	// in-flight requests to complete before the process exits.
	// ---------------------------------------------------------------------------
	srv := &http.Server{
		Addr:    cfg.ServerAddr,
		Handler: router,

		// Timeouts prevent slow clients from holding connections open indefinitely.
		// ReadTimeout: max time to read the entire request (headers + body).
		// WriteTimeout: max time to write the response.
		// IdleTimeout: max time to wait for the next request on a Keep-Alive connection.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start listening in a background goroutine.
	go func() {
		log.Info().Str("addr", cfg.ServerAddr).Msg("HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	// ---------------------------------------------------------------------------
	// 10. Block until SIGTERM or SIGINT, then gracefully drain and exit.
	// ---------------------------------------------------------------------------
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	sig := <-quit

	log.Info().Str("signal", sig.String()).Msg("shutdown signal received; draining connections")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("graceful shutdown timed out; forcing exit")
	} else {
		log.Info().Msg("ATS stopped cleanly")
	}
}

// migrationsPath returns the path to the migrations directory relative to the
// location of the compiled binary. This works for both local development
// (binary in project root) and Docker (binary at /ats, migrations at /migrations).
func migrationsPath() string {
	// Look for migrations/ relative to the binary.
	exe, err := os.Executable()
	if err != nil {
		return "migrations"
	}
	candidate := filepath.Join(filepath.Dir(exe), "migrations")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	// Fallback: assume CWD-relative path (used in `go run ./cmd/ats`).
	return "migrations"
}

// maskDSN replaces the password in a Postgres DSN with "***" for safe logging.
// Example: postgres://user:secret@host/db → postgres://user:***@host/db
func maskDSN(dsn string) string {
	// Simple heuristic: find the password between the second ":" and the "@".
	// Does not handle all edge cases but is safe enough for log output.
	for i := 0; i < len(dsn); i++ {
		if dsn[i] == ':' {
			// Skip "postgres:" prefix
			rest := dsn[i+1:]
			if len(rest) > 2 && rest[:2] == "//" {
				// Found the scheme colon — skip past "//user:"
				userAt := -1
				for j := 2; j < len(rest); j++ {
					if rest[j] == ':' {
						userAt = j
						break
					}
					if rest[j] == '@' {
						break
					}
				}
				if userAt == -1 {
					return dsn
				}
				end := -1
				for j := userAt + 1; j < len(rest); j++ {
					if rest[j] == '@' {
						end = j
						break
					}
				}
				if end == -1 {
					return dsn
				}
				return dsn[:i+1] + rest[:userAt+1] + "***" + rest[end:]
			}
			break
		}
	}
	return dsn
}
