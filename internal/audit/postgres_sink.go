package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// PostgresSink writes audit events to the audit_log table.
//
// The schema (migrations/001_initial_schema.up.sql) is:
//
//	audit_log(id, user_id, organization_id, action, resource_type,
//	          resource_id, ip_address, user_agent, details JSONB, created_at)
//
// Event.ActorUserID maps to user_id (the actor is the one we audit "as").
// Event.SubjectUserID, if different from actor, lives in details. This
// matches the audit-log convention of "user_id = who performed the action."
type PostgresSink struct {
	db *sqlx.DB
}

// NewPostgresSink returns a sink backed by the given sqlx.DB. Passing nil
// returns a NoopSink so callers don't have to check.
func NewPostgresSink(db *sqlx.DB) Sink {
	if db == nil {
		return NoopSink{}
	}
	return &PostgresSink{db: db}
}

func (s *PostgresSink) Write(ctx context.Context, e *Event) error {
	// Merge subject_user_id into details when it differs from actor so we
	// don't lose it. Keeps the column simple while preserving the info.
	details := e.Details
	if e.SubjectUserID != nil && (e.ActorUserID == nil || *e.SubjectUserID != *e.ActorUserID) {
		if details == nil {
			details = map[string]any{}
		}
		details["subject_user_id"] = e.SubjectUserID.String()
	}

	// Default to an untyped nil so the JSONB column receives SQL NULL when
	// there are no details. A typed nil []byte is encoded by lib/pq as an
	// empty string '', which JSONB rejects ("invalid input syntax for type
	// json") — that's the login.success failure, since that event carries
	// no details.
	var detailsJSON any
	if len(details) > 0 {
		b, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
		detailsJSON = b
	}

	const q = `
		INSERT INTO audit_log (
			id, user_id, organization_id, action, resource_type,
			resource_id, ip_address, user_agent, details, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := s.db.ExecContext(ctx, q,
		e.ID,
		e.ActorUserID,
		e.OrganizationID,
		e.Action,
		nullableString(e.ResourceType),
		e.ResourceID,
		nullableString(e.IP),
		nullableString(e.UserAgent),
		detailsJSON,
		e.At,
	)
	if err != nil {
		return fmt.Errorf("audit insert: %w", err)
	}
	return nil
}

// nullableString returns nil for empty strings so we don't write empty
// "" rows when the field wasn't set. Lets DB-level NULL convey absence.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
