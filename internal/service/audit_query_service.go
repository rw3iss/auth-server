package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/rw3iss/auth/pkg/shared/types"
)

// AuditQueryService is read-side access to the audit_log table. The
// existing audit.Writer is write-only (drainer pattern); this service
// reads for the /admin/audit-log endpoint.
//
// Filters are kept narrow (action / user / org / since / until) because
// the table grows monotonically — letting an admin run an unfiltered
// "give me everything" against a million-row table would lock up the
// server. Page size is capped at 200.
type AuditQueryService struct {
	db *sqlx.DB
}

// NewAuditQueryService wires the read service with the shared sqlx handle.
func NewAuditQueryService(db *sqlx.DB) *AuditQueryService {
	return &AuditQueryService{db: db}
}

// AuditEntry is the wire shape for a single audit row.
type AuditEntry struct {
	ID             types.ID  `json:"id" db:"id"`
	UserID         *types.ID `json:"user_id,omitempty" db:"user_id"`
	OrganizationID *types.ID `json:"organization_id,omitempty" db:"organization_id"`
	Action         string    `json:"action" db:"action"`
	ResourceType   *string   `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID     *types.ID `json:"resource_id,omitempty" db:"resource_id"`
	IPAddress      *string   `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      *string   `json:"user_agent,omitempty" db:"user_agent"`
	// Details is JSONB on the server side. Stored as string here so the
	// JSON handler-side can pass it through unparsed to the client; the
	// extra parse → re-marshal trip is wasted work.
	Details   sql.NullString `json:"-" db:"details"`
	CreatedAt time.Time      `json:"created_at" db:"created_at"`
}

// ListInput is the filter set accepted by /admin/audit-log.
type AuditListInput struct {
	Action         string
	UserID         *types.ID
	OrganizationID *types.ID
	Since          *time.Time
	Until          *time.Time
	Page           int
	PageSize       int
}

// ListResult is the paginated response shape.
type AuditListResult struct {
	Entries    []*AuditEntry `json:"entries"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	Total      int           `json:"total"`
}

const maxAuditPageSize = 200

// List returns a page of audit entries matching the filters. Newest first.
//
// SQL safety: every filter binds via $N positional parameters; we
// don't string-concat any user input. Action filter supports a single
// glob prefix ("login.*") by emitting a LIKE — still parameterised.
func (s *AuditQueryService) List(ctx context.Context, in AuditListInput) (*AuditListResult, error) {
	if in.PageSize <= 0 {
		in.PageSize = 50
	}
	if in.PageSize > maxAuditPageSize {
		in.PageSize = maxAuditPageSize
	}
	if in.Page < 1 {
		in.Page = 1
	}

	var where []string
	args := []interface{}{}
	add := func(clause string, val interface{}) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if in.Action != "" {
		if strings.HasSuffix(in.Action, ".*") {
			add("action LIKE $%d", strings.TrimSuffix(in.Action, ".*")+".%%")
		} else {
			add("action = $%d", in.Action)
		}
	}
	if in.UserID != nil {
		add("user_id = $%d", *in.UserID)
	}
	if in.OrganizationID != nil {
		add("organization_id = $%d", *in.OrganizationID)
	}
	if in.Since != nil {
		add("created_at >= $%d", *in.Since)
	}
	if in.Until != nil {
		add("created_at < $%d", *in.Until)
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = "WHERE " + strings.Join(where, " AND ")
	}

	// Total before pagination — separate cheap COUNT(*) so the page
	// itself isn't a window function. The audit table is indexed on
	// every filter column, so COUNT is bounded.
	var total int
	countQ := fmt.Sprintf(`SELECT COUNT(*) FROM audit_log %s`, whereSQL)
	if err := s.db.GetContext(ctx, &total, countQ, args...); err != nil {
		return nil, fmt.Errorf("count audit_log: %w", err)
	}

	offset := (in.Page - 1) * in.PageSize
	args = append(args, in.PageSize, offset)
	listQ := fmt.Sprintf(`
		SELECT id, user_id, organization_id, action, resource_type, resource_id,
			ip_address, user_agent, details, created_at
		FROM audit_log
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		whereSQL, len(args)-1, len(args),
	)
	var rows []*AuditEntry
	if err := s.db.SelectContext(ctx, &rows, listQ, args...); err != nil {
		return nil, fmt.Errorf("select audit_log: %w", err)
	}
	return &AuditListResult{Entries: rows, Page: in.Page, PageSize: in.PageSize, Total: total}, nil
}
