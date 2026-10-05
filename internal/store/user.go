// user.go implements UserStore backed by PostgreSQL via sqlx.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// UserRepo is the concrete PostgreSQL implementation of UserStore.
// It holds a reference to the shared *sqlx.DB connection pool.
// All methods are safe for concurrent use — sqlx.DB is a pool.
type UserRepo struct {
	db *sqlx.DB
}

// NewUserRepo creates a UserRepo wrapping the given database pool.
func NewUserRepo(db *sqlx.DB) *UserRepo {
	return &UserRepo{db: db}
}

// GetByEmail fetches the user whose email matches the given value.
//
// The query uses LOWER() on both sides so that "alice@example.com" and
// "Alice@Example.COM" are treated as the same email. This prevents a user
// from registering twice with different capitalisation.
//
// Returns ErrNotFound (sql.ErrNoRows) if no user exists with that email.
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*User, error) {
	const q = `
		SELECT id, email, password_hash, scopes, disabled
		FROM   users
		WHERE  LOWER(email) = LOWER($1)
		LIMIT  1`

	var u User
	// sqlx.GetContext scans a single row into the struct using the `db:` tags.
	// It returns sql.ErrNoRows (our ErrNotFound) if no row matches.
	err := r.db.GetContext(ctx, &u, q, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("GetByEmail: %w", err)
	}
	return &u, nil
}

// Create inserts a new user row and returns the created record.
//
// The INSERT uses RETURNING to retrieve the generated UUID and timestamps in
// a single round-trip rather than issuing a separate SELECT afterward.
//
// Returns an error if the email already exists (Postgres unique constraint
// violation). The caller is responsible for translating that into a 409 or
// appropriate response — we don't interpret Postgres error codes here.
func (r *UserRepo) Create(ctx context.Context, email, passwordHash string, scopes []string) (*User, error) {
	const q = `
		INSERT INTO users (email, password_hash, scopes)
		VALUES ($1, $2, $3)
		RETURNING id, email, password_hash, scopes, disabled`

	var u User
	err := r.db.GetContext(ctx, &u, q, email, passwordHash, pqStringArray(scopes))
	if err != nil {
		return nil, fmt.Errorf("Create user: %w", err)
	}
	return &u, nil
}

// compile-time assertion: *UserRepo must satisfy UserStore.
var _ UserStore = (*UserRepo)(nil)

// ScopesAsStrings is a convenience helper that converts pqStringArray to
// []string. Used by token minting where []string is expected.
func (u *User) ScopesAsStrings() []string {
	return []string(u.Scopes)
}

