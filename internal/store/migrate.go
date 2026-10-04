// Package store provides all PostgreSQL persistence logic for the ATS.
//
// This file implements the migration runner. Migrations are plain SQL files
// stored in the migrations/ directory. The runner tracks applied migrations
// in a schema_migrations table so each file is applied exactly once, even
// across restarts.
//
// Design decisions:
//
//   - Plain SQL files, not a migration library (goose, migrate, etc.).
//     We want zero abstraction over the SQL — every DBA or reviewer can read
//     the exact DDL being applied without knowing a library's conventions.
//
//   - Files are applied in lexicographic (filename) order.
//     Prefixing files with a zero-padded sequence number (001_, 002_, ...)
//     guarantees a stable, predictable order across all environments.
//
//   - Each file is wrapped in a single transaction. If the SQL fails, the
//     transaction rolls back and the filename is NOT recorded in
//     schema_migrations. The next startup will retry the same file.
//     This keeps migrations atomic: either fully applied or not at all.
//
//   - The schema_migrations table itself is created with IF NOT EXISTS before
//     any migration is applied, so the very first run bootstraps cleanly.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jmoiron/sqlx"
)

// RunMigrations applies all *.sql files in migrationsDir that have not yet
// been recorded in the schema_migrations table.
//
// It is safe to call on every startup — already-applied files are skipped.
// Files are applied in lexicographic order of their base filename.
//
// Returns an error if:
//   - The schema_migrations table cannot be created.
//   - A migration file cannot be read.
//   - A migration SQL fails (the transaction is rolled back; the file is not
//     marked as applied, so the next startup retries it).
func RunMigrations(db *sqlx.DB, migrationsDir string) error {
	// Step 1: ensure the schema_migrations tracking table exists.
	// This DDL is idempotent (IF NOT EXISTS), so it is safe to run every time.
	const createTracking = `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT        NOT NULL PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`
	if _, err := db.Exec(createTracking); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	// Step 2: load the set of already-applied filenames from the tracking table.
	// We store only the base filename (e.g. "001_init.sql"), not the full path,
	// so migrations/ can be moved without invalidating history.
	rows, err := db.Query("SELECT filename FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("query schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan schema_migrations row: %w", err)
		}
		applied[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate schema_migrations rows: %w", err)
	}

	// Step 3: collect all *.sql files in migrationsDir.
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read migrations directory %q: %w", migrationsDir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}

	// Sort lexicographically so 001_ always runs before 002_, etc.
	sort.Strings(files)

	// Step 4: apply each unapplied file in order.
	for _, name := range files {
		if applied[name] {
			// Already applied on a previous run — skip silently.
			continue
		}

		if err := applyMigration(db, migrationsDir, name); err != nil {
			return fmt.Errorf("apply migration %q: %w", name, err)
		}
	}

	return nil
}

// applyMigration reads a single SQL file and executes it inside a transaction.
// On success, it records the filename in schema_migrations within the same
// transaction so the file and its tracking record are committed atomically.
func applyMigration(db *sqlx.DB, dir, filename string) error {
	path := filepath.Join(dir, filename)

	// Read the entire SQL file into memory. Migration files are small
	// (a few KB at most) so this is safe and avoids streaming complexity.
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// Wrap in a transaction so the DDL and the tracking INSERT succeed or fail
	// together. If the SQL fails, the tracking row is not written — next startup
	// retries the migration.
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	// Ensure the transaction is rolled back if we return an error below.
	// If Commit() is called first, this Rollback() becomes a no-op.
	defer tx.Rollback() //nolint:errcheck

	// Execute the full SQL file as a single statement batch.
	// PostgreSQL supports multiple statements in one Exec call when separated
	// by semicolons, which is the standard format for our migration files.
	if _, err := tx.Exec(string(content)); err != nil {
		return fmt.Errorf("execute SQL: %w", err)
	}

	// Record this file as applied within the same transaction.
	if _, err := tx.Exec(
		"INSERT INTO schema_migrations (filename) VALUES ($1)", filename,
	); err != nil {
		return fmt.Errorf("record migration in schema_migrations: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}
