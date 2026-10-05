// Package cache provides a write-through Redis revocation cache for the ATS.
//
// # Responsibility
//
// Speed up the hot-path revocation check on POST /auth/refresh by caching
// revoked refresh token IDs in Redis with a TTL matching the token's remaining
// lifetime. This avoids a Postgres read on every refresh request for tokens
// that are already known to be revoked.
//
// # Authority model
//
// Redis is NOT the source of truth. Postgres is. Redis holds only a
// best-effort cache of positive revocations. The system behaves correctly
// even if Redis is completely unavailable — handlers fall through to Postgres.
//
// # Three-value IsRevoked return
//
//	revoked=true          → fast-path reject; skip Postgres (Redis trusted for positive hits)
//	err != nil            → Redis error; fall through to Postgres
//	revoked=false, ok=false → cache miss; fall through to Postgres
//	revoked=false, ok=true  → Redis explicitly says not-revoked; fall through to Postgres
//	                          (Postgres is still authoritative for existence and expiry)
//
// # Failure policy
//
// A Redis write failure does NOT cause the overall operation to fail. SetRevoked
// logs the error and swallows it. A missing Redis entry is safely handled by
// the Postgres fallback path. The only consequence of a Redis outage is higher
// Postgres load on the refresh endpoint.
package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// keyPrefix is prepended to every revocation key stored in Redis.
// Namespacing prevents collisions with other applications sharing the same
// Redis instance and makes it easy to identify ATS keys in monitoring tools.
const keyPrefix = "ats:revoked:"

// Cache wraps a Redis client and exposes revocation-specific helpers.
type Cache struct {
	client *redis.Client
}

// NewCache creates a Cache that connects to the Redis server at addr.
//
// password may be empty if Redis does not require authentication.
//
// A Ping is sent at construction time. If Redis is unreachable, a warning is
// logged but no error is returned — the service starts and uses Postgres
// exclusively until Redis becomes available.
func NewCache(addr, password string) *Cache {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,

		// DialTimeout: how long to wait when establishing a new connection.
		// 2 seconds is generous for a local/container Redis; adjust for remote.
		DialTimeout: 2 * time.Second,

		// ReadTimeout / WriteTimeout: per-operation deadlines.
		// Keeps a slow Redis from blocking the HTTP handler for too long.
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	})

	// Attempt a startup ping. We use a short context so a down Redis doesn't
	// delay startup for more than ~2 seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		// Log a warning, not a fatal — Redis being down at startup is recoverable.
		// The handlers will fall through to Postgres until Redis comes back.
		log.Warn().
			Str("redis_addr", addr).
			Err(err).
			Msg("Redis ping failed at startup; revocation cache disabled until Redis recovers")
	} else {
		log.Info().
			Str("redis_addr", addr).
			Msg("Redis connection established")
	}

	return &Cache{client: client}
}

// SetRevoked writes a revocation entry for tokenID to Redis with the given TTL.
//
// The key is "ats:revoked:<tokenID>" and the value is "1" (arbitrary — we
// only care about key presence, not value).
//
// TTL should be set to the token's remaining lifetime so the key expires
// naturally when the token would have expired anyway, keeping Redis lean.
//
// This is a best-effort write: errors are logged but not returned. A Redis
// write failure does NOT prevent the token from being revoked in Postgres.
func (c *Cache) SetRevoked(ctx context.Context, tokenID string, ttl time.Duration) {
	key := keyPrefix + tokenID
	if err := c.client.Set(ctx, key, "1", ttl).Err(); err != nil {
		// Log at warn level — this is unexpected but not fatal.
		// The Postgres record is the authoritative revocation; Redis is cache.
		log.Warn().
			Str("token_id", tokenID).
			Err(err).
			Msg("Redis SetRevoked failed; token revoked in Postgres but not cached")
	}
}

// IsRevoked checks whether tokenID has a revocation entry in Redis.
//
// Return values:
//
//	(true,  true,  nil) → key found: token is positively revoked → reject immediately
//	(false, false, nil) → key missing (cache miss) → fall through to Postgres
//	(false, false, err) → Redis error → fall through to Postgres
//
// The caller MUST fall through to Postgres on any result except (true, true, nil).
func (c *Cache) IsRevoked(ctx context.Context, tokenID string) (revoked bool, ok bool, err error) {
	key := keyPrefix + tokenID

	val, redisErr := c.client.Get(ctx, key).Result()
	if redisErr != nil {
		if errors.Is(redisErr, redis.Nil) {
			// redis.Nil means the key does not exist (cache miss).
			// This is not an error — it means Redis has no knowledge of this token.
			// Fall through to Postgres.
			return false, false, nil
		}
		// Any other error (timeout, connection refused, etc.) — treat as a miss
		// and fall through to Postgres. Log so operations can alert on Redis health.
		log.Warn().
			Str("token_id", tokenID).
			Err(redisErr).
			Msg("Redis IsRevoked error; falling through to Postgres")
		return false, false, fmt.Errorf("redis get: %w", redisErr)
	}

	// Key exists. The value is "1" by convention but we don't validate it —
	// presence of the key is the revocation signal.
	_ = val
	return true, true, nil
}

// Ping checks the Redis connection. Used by health/ready endpoints to report
// Redis availability status without being a hard failure.
func (c *Cache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}
