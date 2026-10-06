// types.go provides custom scan/value types that bridge PostgreSQL-specific
// wire formats and Go native types.
package store

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

// NewStringArray converts a []string to pqStringArray for use in INSERT/UPDATE
// queries. This is the outward-facing constructor used by handler code that
// builds store.RefreshToken values.
func NewStringArray(s []string) pqStringArray {
	return pqStringArray(s)
}

// pqStringArray is a []string that implements database/sql's Scanner and
// driver.Valuer interfaces for PostgreSQL text[] columns.
//
// Why not use lib/pq's pq.Array helper?
// We depend on pgx as the Postgres driver, not lib/pq. pgx's stdlib wrapper
// does not expose pq.Array. Writing a small custom type here keeps us
// driver-agnostic and removes the lib/pq dependency entirely.
//
// Wire format: PostgreSQL sends text arrays as {val1,val2,"val with spaces"}.
// We parse that literal here.
type pqStringArray []string

// Scan implements sql.Scanner. Called when sqlx reads a column value into a
// pqStringArray field.
func (a *pqStringArray) Scan(src any) error {
	if src == nil {
		*a = nil
		return nil
	}

	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("pqStringArray.Scan: unsupported source type %T", src)
	}

	// PostgreSQL represents an empty array as "{}".
	if s == "{}" {
		*a = []string{}
		return nil
	}

	// Strip surrounding braces: "{a,b,c}" → "a,b,c"
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")

	// Split on commas, but respect double-quoted elements that may contain commas.
	// We use a simple state-machine parser rather than a regex to keep it readable.
	var result []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"' && !inQuotes:
			inQuotes = true
		case ch == '"' && inQuotes:
			inQuotes = false
		case ch == ',' && !inQuotes:
			result = append(result, current.String())
			current.Reset()
		default:
			current.WriteByte(ch)
		}
	}
	// Append the last element (no trailing comma).
	result = append(result, current.String())

	*a = result
	return nil
}

// Value implements driver.Valuer. Called when sqlx writes a pqStringArray
// field into a query parameter.
//
// We emit the PostgreSQL array literal format: {val1,val2,"val with comma,here"}
func (a pqStringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	if len(a) == 0 {
		return "{}", nil
	}

	var sb strings.Builder
	sb.WriteByte('{')
	for i, v := range a {
		if i > 0 {
			sb.WriteByte(',')
		}
		// Quote elements that contain commas, double quotes, or braces.
		if strings.ContainsAny(v, `{},"\`) {
			sb.WriteByte('"')
			// Escape internal double quotes.
			sb.WriteString(strings.ReplaceAll(v, `"`, `\"`))
			sb.WriteByte('"')
		} else {
			sb.WriteString(v)
		}
	}
	sb.WriteByte('}')
	return sb.String(), nil
}
