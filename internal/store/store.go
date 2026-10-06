// Package store defines the repository interfaces and shared model types for
// all PostgreSQL persistence operations in the ATS.
//
// Architecture: thin repository pattern.
//
//   - Interfaces live here (store.go). They are the contract between handlers
//     and the database. Handlers depend only on the interface, not on *sqlx.DB,
//     making them testable with in-process fakes.
//
//   - Concrete implementations live in user.go, service_account.go, and
//     refresh_token.go. They import sqlx and own all SQL.
//
//   - No ORM. Every query is visible, named, and auditable.
//
// All repository methods take context.Context as the first argument so that
// HTTP request deadlines propagate into database queries. A slow query will
// be cancelled when the HTTP client disconnects or the request timeout fires.
package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrNotFound is returned by repository Get methods when the requested row
// does not exist. Handlers map this to 401 (not 404) for auth resources to
// avoid leaking whether an email/client_id exists.
var ErrNotFound = sql.ErrNoRows

// ---------------------------------------------------------------------------
// Model types
// ---------------------------------------------------------------------------

// User represents a human user who authenticates via the password grant.
type User struct {
	ID           uuid.UUID      `db:"id"`
	Email        string         `db:"email"`
	PasswordHash string         `db:"password_hash"`
	Scopes       pqStringArray  `db:"scopes"`
	Disabled     bool           `db:"disabled"`
}

// ServiceAccount represents an M2M client authenticating via client credentials.
type ServiceAccount struct {
	ID               uuid.UUID     `db:"id"`
	ClientID         string        `db:"client_id"`
	ClientSecretHash string        `db:"client_secret_hash"`
	Scopes           pqStringArray `db:"scopes"`
	Disabled         bool          `db:"disabled"`
}

// RefreshToken represents a single issued refresh token row.
type RefreshToken struct {
	ID          uuid.UUID     `db:"id"`
	TokenHash   string        `db:"token_hash"`
	Subject     uuid.UUID     `db:"subject"`
	SubjectType string        `db:"subject_type"`
	Scopes      pqStringArray `db:"scopes"`
	IssuedAt    time.Time     `db:"issued_at"`
	ExpiresAt   time.Time     `db:"expires_at"`
	Revoked     bool          `db:"revoked"`
	RevokedAt   *time.Time    `db:"revoked_at"` // nil if not revoked
}

// ---------------------------------------------------------------------------
// Repository interfaces
// ---------------------------------------------------------------------------

// UserStore defines all database operations on the users table.
type UserStore interface {
	// GetByEmail returns the user with the given email, or ErrNotFound if no
	// such user exists.
	GetByEmail(ctx context.Context, email string) (*User, error)

	// Create inserts a new user row. Returns an error if the email already exists.
	Create(ctx context.Context, email, passwordHash string, scopes []string) (*User, error)
}

// ServiceAccountStore defines all database operations on the service_accounts table.
type ServiceAccountStore interface {
	// GetByClientID returns the service account for the given client_id, or
	// ErrNotFound if not present.
	GetByClientID(ctx context.Context, clientID string) (*ServiceAccount, error)

	// Create inserts a new service account row.
	Create(ctx context.Context, clientID, secretHash string, scopes []string) (*ServiceAccount, error)
}

// RefreshTokenStore defines all database operations on the refresh_tokens table.
type RefreshTokenStore interface {
	// Insert writes a new refresh token row. Called after token minting.
	Insert(ctx context.Context, token *RefreshToken) error

	// GetByHash fetches a token row by its hash without locking.
	// Used by the /auth/revoke handler which does not need a row lock.
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)

	// GetByHashForUpdate fetches the row for tokenHash and locks it with
	// SELECT FOR UPDATE. tx must be an active *sql.Tx.
	//
	// The row lock prevents a concurrent rotation from reading the same row
	// before the current transaction revokes it — eliminating the TOCTOU race
	// where two requests both think the same refresh token is valid.
	//
	// Returns ErrNotFound if no row matches tokenHash.
	GetByHashForUpdate(ctx context.Context, tx *sql.Tx, tokenHash string) (*RefreshToken, error)

	// Revoke marks a token row as revoked (revoked=true, revoked_at=NOW()).
	// tx may be nil for non-transactional revocations (e.g. explicit /revoke).
	// When tx is non-nil the update is part of the rotation transaction.
	Revoke(ctx context.Context, tx *sql.Tx, tokenID uuid.UUID) error

	// DeleteExpired deletes rows whose expires_at < NOW(). Returns the number
	// of rows deleted. Called by a maintenance job, not on the hot path.
	DeleteExpired(ctx context.Context) (int64, error)
}
