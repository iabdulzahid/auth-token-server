package config_test

import (
	"testing"

	"github.com/iabdulzahid/auth-token-server/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoad_MissingRequired verifies that Load returns an error when required
// environment variables are absent, and that ALL missing vars are reported
// together — not just the first one.
func TestLoad_MissingRequired(t *testing.T) {
	// t.Setenv automatically restores the original value after the test.
	// This is safer than os.Setenv because it handles cleanup even on test failure.
	t.Setenv("DATABASE_DSN", "")
	t.Setenv("REDIS_ADDR", "")
	t.Setenv("RSA_PRIVATE_KEY_PEM", "")

	_, err := config.Load()
	require.Error(t, err)

	// All three missing variables must appear in the single error message.
	assert.Contains(t, err.Error(), "DATABASE_DSN")
	assert.Contains(t, err.Error(), "REDIS_ADDR")
	assert.Contains(t, err.Error(), "RSA_PRIVATE_KEY_PEM")
}

// TestLoad_Defaults verifies that optional fields are populated with their
// documented default values when the corresponding env vars are not set.
func TestLoad_Defaults(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://user:pass@localhost:5432/ats?sslmode=disable")
	t.Setenv("REDIS_ADDR", "localhost:6379")
	t.Setenv("RSA_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----")

	// Ensure optional vars are absent so defaults kick in.
	t.Setenv("ACCESS_TOKEN_TTL", "")
	t.Setenv("REFRESH_TOKEN_TTL", "")
	t.Setenv("SERVER_ADDR", "")
	t.Setenv("BCRYPT_COST", "")
	t.Setenv("REDIS_PASSWORD", "")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "15m0s", cfg.AccessTokenTTL.String())
	assert.Equal(t, "168h0m0s", cfg.RefreshTokenTTL.String())
	assert.Equal(t, ":8080", cfg.ServerAddr)
	assert.Equal(t, 12, cfg.BcryptCost)
	assert.Equal(t, "", cfg.RedisPassword)
}

// TestLoad_CustomValues verifies that explicitly set optional fields override defaults.
func TestLoad_CustomValues(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://user:pass@localhost:5432/ats?sslmode=disable")
	t.Setenv("REDIS_ADDR", "redis:6379")
	t.Setenv("REDIS_PASSWORD", "secret")
	t.Setenv("RSA_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----")
	t.Setenv("ACCESS_TOKEN_TTL", "30m")
	t.Setenv("REFRESH_TOKEN_TTL", "336h")
	t.Setenv("SERVER_ADDR", ":9090")
	t.Setenv("BCRYPT_COST", "14")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "30m0s", cfg.AccessTokenTTL.String())
	assert.Equal(t, "336h0m0s", cfg.RefreshTokenTTL.String())
	assert.Equal(t, ":9090", cfg.ServerAddr)
	assert.Equal(t, 14, cfg.BcryptCost)
	assert.Equal(t, "secret", cfg.RedisPassword)
}

// TestLoad_InvalidDuration verifies that a malformed duration string produces
// a clear error rather than silently using a zero value.
func TestLoad_InvalidDuration(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://user:pass@localhost:5432/ats?sslmode=disable")
	t.Setenv("REDIS_ADDR", "localhost:6379")
	t.Setenv("RSA_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----")
	t.Setenv("ACCESS_TOKEN_TTL", "fifteen minutes") // invalid

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACCESS_TOKEN_TTL")
	assert.Contains(t, err.Error(), "fifteen minutes")
}

// TestLoad_InvalidBcryptCost verifies that an out-of-range bcrypt cost fails clearly.
func TestLoad_InvalidBcryptCost(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://user:pass@localhost:5432/ats?sslmode=disable")
	t.Setenv("REDIS_ADDR", "localhost:6379")
	t.Setenv("RSA_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----")
	t.Setenv("BCRYPT_COST", "5") // below minimum of 10

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BCRYPT_COST")
}
