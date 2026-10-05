// service_account.go implements ServiceAccountStore backed by PostgreSQL via sqlx.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// ServiceAccountRepo is the concrete PostgreSQL implementation of ServiceAccountStore.
type ServiceAccountRepo struct {
	db *sqlx.DB
}

// NewServiceAccountRepo creates a ServiceAccountRepo wrapping the given pool.
func NewServiceAccountRepo(db *sqlx.DB) *ServiceAccountRepo {
	return &ServiceAccountRepo{db: db}
}

// GetByClientID fetches the service account whose client_id matches exactly.
//
// client_id is the public identifier sent by M2M services. We match it
// case-sensitively (no LOWER()) because service account IDs are slugs that
// should be compared exactly — unlike user emails which may have mixed case.
//
// Returns ErrNotFound if no account exists for that client_id.
func (r *ServiceAccountRepo) GetByClientID(ctx context.Context, clientID string) (*ServiceAccount, error) {
	const q = `
		SELECT id, client_id, client_secret_hash, scopes, disabled
		FROM   service_accounts
		WHERE  client_id = $1
		LIMIT  1`

	var sa ServiceAccount
	err := r.db.GetContext(ctx, &sa, q, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("GetByClientID: %w", err)
	}
	return &sa, nil
}

// Create inserts a new service account row.
//
// secretHash is a bcrypt digest of the raw client secret. The raw secret is
// generated once and returned to the caller — it is never stored here.
//
// Returns an error if the client_id already exists.
func (r *ServiceAccountRepo) Create(ctx context.Context, clientID, secretHash string, scopes []string) (*ServiceAccount, error) {
	const q = `
		INSERT INTO service_accounts (client_id, client_secret_hash, scopes)
		VALUES ($1, $2, $3)
		RETURNING id, client_id, client_secret_hash, scopes, disabled`

	var sa ServiceAccount
	err := r.db.GetContext(ctx, &sa, q, clientID, secretHash, pqStringArray(scopes))
	if err != nil {
		return nil, fmt.Errorf("Create service_account: %w", err)
	}
	return &sa, nil
}

// compile-time assertion: *ServiceAccountRepo must satisfy ServiceAccountStore.
var _ ServiceAccountStore = (*ServiceAccountRepo)(nil)

// ScopesAsStrings converts pqStringArray to []string for token minting.
func (sa *ServiceAccount) ScopesAsStrings() []string {
	return []string(sa.Scopes)
}
