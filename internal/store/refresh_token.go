// refresh_token.go implements RefreshTokenStore backed by PostgreSQL via sqlx.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// RefreshTokenRepo is the concrete PostgreSQL implementation of RefreshTokenStore.
type RefreshTokenRepo struct {
	db *sqlx.DB
}

// NewRefreshTokenRepo creates a RefreshTokenRepo wrapping the given pool.
func NewRefreshTokenRepo(db *sqlx.DB) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}

// Insert writes a new refresh token row.
//
// The token row is created with revoked=false and no revoked_at. The id,
// issued_at, and expires_at are set by the caller (token.go) to keep minting
// logic centralised there.
func (r *RefreshTokenRepo) Insert(ctx context.Context, token *RefreshToken) error {
	const q = `
		INSERT INTO refresh_tokens
			(id, token_hash, subject, subject_type, scopes, issued_at, expires_at)
		VALUES
			(:id, :token_hash, :subject, :subject_type, :scopes, :issued_at, :expires_at)`

	// sqlx.NamedExecContext maps struct fields to :name placeholders using
	// the `db:` struct tags. This is cleaner than positional $1..$N when
	// the number of columns is large.
	_, err := r.db.NamedExecContext(ctx, q, token)
	if err != nil {
		return fmt.Errorf("Insert refresh token: %w", err)
	}
	return nil
}

// GetByHashForUpdate fetches the refresh token row that matches tokenHash
// and acquires a row-level lock using SELECT FOR UPDATE.
//
// This must be called inside an active database transaction (tx). The lock
// is held until the transaction commits or rolls back. This prevents two
// concurrent requests from both seeing the same token as valid and each
// issuing a new token pair — the second request blocks until the first
// transaction completes, then sees revoked=true and returns 401.
//
// Returns ErrNotFound if no row exists for tokenHash.
func (r *RefreshTokenRepo) GetByHashForUpdate(ctx context.Context, tx *sql.Tx, tokenHash string) (*RefreshToken, error) {
	const q = `
		SELECT id, token_hash, subject, subject_type, scopes,
		       issued_at, expires_at, revoked, revoked_at
		FROM   refresh_tokens
		WHERE  token_hash = $1
		FOR UPDATE`

	row := tx.QueryRowContext(ctx, q, tokenHash)

	var rt RefreshToken
	err := row.Scan(
		&rt.ID,
		&rt.TokenHash,
		&rt.Subject,
		&rt.SubjectType,
		&rt.Scopes,
		&rt.IssuedAt,
		&rt.ExpiresAt,
		&rt.Revoked,
		&rt.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("GetByHashForUpdate: %w", err)
	}
	return &rt, nil
}

// Revoke marks a refresh token as revoked.
//
// When tx is non-nil, the UPDATE runs inside the caller's transaction (used
// during token rotation — old token revoked and new token inserted atomically).
// When tx is nil, the UPDATE runs directly against the pool (used for
// explicit /auth/revoke calls where no rotation is needed).
//
// Sets revoked=true and revoked_at=NOW() in a single UPDATE. We update both
// columns because:
//   - revoked (bool) has a partial index and is fast to query.
//   - revoked_at (timestamptz) records when revocation happened for audits.
func (r *RefreshTokenRepo) Revoke(ctx context.Context, tx *sql.Tx, tokenID uuid.UUID) error {
	const q = `
		UPDATE refresh_tokens
		SET    revoked = TRUE, revoked_at = NOW()
		WHERE  id = $1`

	var err error
	if tx != nil {
		// Run inside the caller's transaction.
		_, err = tx.ExecContext(ctx, q, tokenID)
	} else {
		// Run directly against the pool — no active transaction.
		_, err = r.db.ExecContext(ctx, q, tokenID)
	}
	if err != nil {
		return fmt.Errorf("Revoke refresh token: %w", err)
	}
	return nil
}

// DeleteExpired removes all refresh token rows whose expires_at < NOW().
//
// This is not called on the hot path. It should be run periodically (e.g. by
// a cron job or a maintenance goroutine) to keep the table from growing
// unboundedly. Expired tokens are already functionally invalid, so deleting
// them has no correctness impact.
//
// Returns the number of rows deleted.
func (r *RefreshTokenRepo) DeleteExpired(ctx context.Context) (int64, error) {
	const q = `DELETE FROM refresh_tokens WHERE expires_at < NOW()`

	res, err := r.db.ExecContext(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("DeleteExpired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("DeleteExpired rows affected: %w", err)
	}
	return n, nil
}

// compile-time assertion: *RefreshTokenRepo must satisfy RefreshTokenStore.
var _ RefreshTokenStore = (*RefreshTokenRepo)(nil)

// ScopesAsStrings converts pqStringArray to []string for token minting.
func (rt *RefreshToken) ScopesAsStrings() []string {
	return []string(rt.Scopes)
}

// IsExpired returns true if the token's expiry has passed relative to now.
// Used by handlers to check expiry after the SELECT FOR UPDATE row is fetched.
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().UTC().After(rt.ExpiresAt.UTC())
}
