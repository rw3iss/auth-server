package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/repository"
	sharederrors "github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// M2MClientRepository implements repository.M2MClientRepository against
// Postgres via sqlx. One row per registered OAuth2 client_credentials
// consumer (table `m2m_clients`, migration 012).
//
// The hot path is GetByClientID (read on every /oauth/token grant) —
// indexed on m2m_clients(client_id) WHERE revoked_at IS NULL.
type M2MClientRepository struct {
	db *DB
}

// NewM2MClientRepository wires the repo with the shared sqlx handle.
func NewM2MClientRepository(db *DB) *M2MClientRepository {
	return &M2MClientRepository{db: db}
}

// m2mClientSelectCols is the canonical column list — keep in sync with
// the migration. Centralised so adding a field is a one-line edit.
const m2mClientSelectCols = `id, client_id, client_secret_hash, name, description,
	scopes, allowed_audiences, status, created_at, updated_at,
	last_used_at, revoked_at, created_by`

// Create inserts a new M2M client. The plaintext secret must be hashed
// by the caller (service layer uses utils.HashPassword with the
// configured bcrypt cost).
//
// Returns sharederrors.UserAlreadyExists-shaped error when the
// client_id collides — caller surfaces as 409. (We reuse the existing
// error code rather than introducing a parallel one; client_id is
// conceptually a unique identifier same as user email.)
func (r *M2MClientRepository) Create(ctx context.Context, c *domain.M2MClient) error {
	query := `
		INSERT INTO m2m_clients (
			id, client_id, client_secret_hash, name, description,
			scopes, allowed_audiences, status, created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)`

	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx, query,
		c.ID, c.ClientID, c.ClientSecretHash, c.Name, c.Description,
		c.Scopes, c.AllowedAudiences, c.Status, c.CreatedAt, c.UpdatedAt, c.CreatedBy,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return sharederrors.InvalidInput("client_id", "client_id already exists")
		}
		return fmt.Errorf("failed to create m2m client: %w", err)
	}
	return nil
}

// GetByID fetches a client by its UUID primary key. Returns
// sharederrors.NotFound when no row matches.
func (r *M2MClientRepository) GetByID(ctx context.Context, id types.ID) (*domain.M2MClient, error) {
	query := `SELECT ` + m2mClientSelectCols + ` FROM m2m_clients WHERE id = $1`
	c := &domain.M2MClient{}
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, c, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sharederrors.NotFound("m2m_client")
		}
		return nil, fmt.Errorf("failed to get m2m client: %w", err)
	}
	return c, nil
}

// GetByClientID is the hot-path lookup used by /oauth/token. Returns
// the row regardless of status — the service layer makes the call on
// whether to issue a token (so the same NotFound shape is used for
// missing + revoked + disabled, preventing client_id enumeration via
// timing or error-message comparison).
//
// Filters revoked rows via the partial index, but doesn't filter by
// status — disabled clients still appear so the grant handler can
// detect them and apply the constant-time failure path.
func (r *M2MClientRepository) GetByClientID(ctx context.Context, clientID string) (*domain.M2MClient, error) {
	query := `SELECT ` + m2mClientSelectCols + ` FROM m2m_clients
		WHERE client_id = $1 AND revoked_at IS NULL`
	c := &domain.M2MClient{}
	q := getQuerier(ctx, r.db)
	if err := q.GetContext(ctx, c, query, clientID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sharederrors.NotFound("m2m_client")
		}
		return nil, fmt.Errorf("failed to get m2m client: %w", err)
	}
	return c, nil
}

// List returns all non-revoked clients ordered by created_at DESC.
// Pagination is intentionally omitted — M2M client inventories are
// always small (tens, not thousands); a single page is the right shape.
func (r *M2MClientRepository) List(ctx context.Context) ([]*domain.M2MClient, error) {
	query := `SELECT ` + m2mClientSelectCols + ` FROM m2m_clients
		WHERE revoked_at IS NULL ORDER BY created_at DESC`
	var out []*domain.M2MClient
	q := getQuerier(ctx, r.db)
	if err := q.SelectContext(ctx, &out, query); err != nil {
		return nil, fmt.Errorf("failed to list m2m clients: %w", err)
	}
	return out, nil
}

// Revoke marks a client as revoked. Idempotent — a second call is a
// no-op (the WHERE clause filters already-revoked rows out).
func (r *M2MClientRepository) Revoke(ctx context.Context, id types.ID) error {
	q := getQuerier(ctx, r.db)
	_, err := q.ExecContext(ctx,
		`UPDATE m2m_clients SET revoked_at = NOW(), updated_at = NOW()
		 WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("failed to revoke m2m client: %w", err)
	}
	return nil
}

// StampLastUsed updates last_used_at on a successful grant. Fire-and-
// forget — failure is logged but doesn't fail the grant (the token is
// already valid; bookkeeping is a hint, not authoritative). The service
// layer is responsible for any logging.
func (r *M2MClientRepository) StampLastUsed(ctx context.Context, id types.ID) error {
	q := getQuerier(ctx, r.db)
	now := time.Now().UTC()
	_, err := q.ExecContext(ctx,
		`UPDATE m2m_clients SET last_used_at = $2, updated_at = $2 WHERE id = $1`,
		id, now)
	if err != nil {
		return fmt.Errorf("failed to stamp m2m_clients.last_used_at: %w", err)
	}
	return nil
}

// Compile-time assertion that the postgres impl satisfies the contract.
var _ repository.M2MClientRepository = (*M2MClientRepository)(nil)
