-- migrations/001_init.sql
--
-- Initial schema for the Auth Token Server (ATS).
--
-- Design principles:
--   - UUID primary keys: avoids sequential integer enumeration attacks, globally
--     unique across DB replicas or shards if we ever need them.
--   - `scopes` is a PostgreSQL text[] array rather than a separate join table.
--     ATS scope lists are small (< 20 items), append-only, and always read as a
--     whole unit — a normalised table would add a join with no benefit.
--   - `revoked_at` on refresh_tokens is a nullable timestamptz (not a bool alone).
--     It serves double duty: revocation status AND audit trail (when was it revoked?).
--     `revoked` (bool) is kept for fast index-friendly queries.
--   - All timestamps are `timestamptz` (timezone-aware). Storing UTC is not enough
--     on its own — `timestamptz` ensures Postgres normalises to UTC internally and
--     returns the correct wall-clock time regardless of session timezone.
--   - `disabled` on users/service_accounts is a soft-delete that prevents login
--     without destroying audit history.

-- ---------------------------------------------------------------------------
-- Track applied migrations
-- ---------------------------------------------------------------------------
-- This table is the migration runner's own state. RunMigrations inserts a row
-- here after successfully applying each file, and skips files already present.
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   TEXT        NOT NULL PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
-- Represents human users who authenticate via the password grant flow.
CREATE TABLE IF NOT EXISTS users (
    id            UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,

    -- email is the unique login identifier. Stored lower-cased by convention
    -- (enforced by the application layer, not a DB constraint).
    email         TEXT        NOT NULL UNIQUE,

    -- password_hash is a bcrypt digest of the user's password.
    -- We never store the raw password. The cost factor is set in config
    -- (default 12). The hash includes the cost factor, salt, and digest —
    -- a single column is all that is needed.
    password_hash TEXT        NOT NULL,

    -- scopes is the set of permission scopes this user is allowed to request.
    -- When issuing a token, the requested scopes are intersected with this list.
    -- Example: {"read:orders", "write:orders", "admin"}
    scopes        TEXT[]      NOT NULL DEFAULT '{}',

    -- disabled = true prevents login. Set instead of hard-deleting users so
    -- foreign-key references from refresh_tokens remain valid for audit queries.
    disabled      BOOLEAN     NOT NULL DEFAULT FALSE,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- service_accounts
-- ---------------------------------------------------------------------------
-- Represents machine-to-machine (M2M) clients that authenticate via the
-- client credentials grant flow using client_id + client_secret.
CREATE TABLE IF NOT EXISTS service_accounts (
    id                  UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,

    -- client_id is the public identifier sent by the service in each request.
    -- It is a readable slug (e.g. "billing-service") rather than a UUID so
    -- it is easy to identify in logs.
    client_id           TEXT        NOT NULL UNIQUE,

    -- client_secret_hash is a bcrypt digest of the client secret.
    -- The raw secret is generated once (at account creation) and never stored.
    client_secret_hash  TEXT        NOT NULL,

    -- scopes granted to this service account (same semantics as users.scopes).
    scopes              TEXT[]      NOT NULL DEFAULT '{}',

    -- disabled = true prevents authentication for this service account.
    disabled            BOOLEAN     NOT NULL DEFAULT FALSE,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- refresh_tokens
-- ---------------------------------------------------------------------------
-- Each row represents one issued refresh token. This is the authoritative
-- record of whether a token is valid — Redis is only a cache of revocations.
--
-- Security note: we store a SHA-256 hash of the raw token bytes, never the
-- raw token itself. If this table is exfiltrated, the attacker cannot use the
-- hashes directly — they would need to invert SHA-256 (computationally infeasible).
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id           UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,

    -- token_hash is hex(SHA-256(raw_token_bytes)).
    -- The raw token is a 32-byte crypto/rand value, base64url-encoded, returned
    -- to the client exactly once. Only the hash is persisted here.
    token_hash   TEXT        NOT NULL UNIQUE,

    -- subject is the UUID of the user or service_account that owns this token.
    -- We do not foreign-key to users/service_accounts directly because subject_type
    -- determines which table to join, and cross-table FK constraints are awkward.
    subject      UUID        NOT NULL,

    -- subject_type distinguishes the grant flow that produced this token.
    -- "user"            → password grant, subject references users.id
    -- "service_account" → client credentials grant, subject references service_accounts.id
    subject_type TEXT        NOT NULL CHECK (subject_type IN ('user', 'service_account')),

    -- scopes embedded at issuance time. Stored here so a rotated token carries
    -- the same scopes as the original without re-querying the user/service_account.
    scopes       TEXT[]      NOT NULL DEFAULT '{}',

    issued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,

    -- revoked = true means this token has been invalidated (by explicit revoke
    -- or by token rotation — the old token is revoked when a new one is issued).
    revoked      BOOLEAN     NOT NULL DEFAULT FALSE,

    -- revoked_at records when revocation happened. NULL means not revoked.
    -- Useful for security audits: "when was this session terminated and by what path?"
    revoked_at   TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

-- refresh token lookup by hash — the primary hot path on every /auth/refresh
-- and /auth/revoke call. token_hash already has a UNIQUE constraint (which
-- implicitly creates an index), but naming it explicitly aids monitoring.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash
    ON refresh_tokens (token_hash);

-- look up all active tokens for a subject — used during logout-all-devices
-- and for admin tooling. Partial index on non-revoked tokens keeps it small.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_subject_active
    ON refresh_tokens (subject)
    WHERE revoked = FALSE;

-- expired token cleanup: a background job (or manual query) can efficiently
-- find and delete tokens past their expiry.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens (expires_at);
