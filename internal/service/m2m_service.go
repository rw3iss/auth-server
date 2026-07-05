package service

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"

	"github.com/lib/pq"

	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/internal/repository"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
	"github.com/rw3iss/auth/pkg/shared/utils"
)

// M2MService orchestrates the OAuth2 client_credentials lifecycle:
// admin-side client CRUD and consumer-facing token issuance. Sits between
// the OAuth handler / M2M admin handlers and the M2MClientRepository, with
// the JWT service as a collaborator for token minting.
//
// Closes the AUTH_REGISTRATION_TOKEN shim called out in
// auth-server-client/README.md: rotatable, revocable, scope-limited
// credentials in place of the pre-issued long-lived JWT.
//
// SOLID note:
//   - Single responsibility: M2M lifecycle only (no user, no org).
//   - Dependency inversion: repo + jwt service are interfaces / concrete
//     types injected at construction time, never package-globals — keeps
//     tests trivial.
type M2MService struct {
	repo       repository.M2MClientRepository
	jwt        *jwt.Service
	bcryptCost int
	log        *slog.Logger
}

// NewM2MService constructs the service. bcryptCost is sourced from
// config.Security.BcryptCost so secret-hashing matches user password
// hashing (12 by default; configurable to 14 for high-trust deployments).
func NewM2MService(repo repository.M2MClientRepository, jwtSvc *jwt.Service, bcryptCost int, log *slog.Logger) *M2MService {
	if log == nil {
		log = slog.Default()
	}
	return &M2MService{
		repo:       repo,
		jwt:        jwtSvc,
		bcryptCost: bcryptCost,
		log:        log,
	}
}

// CreateClientInput is the validated input for client creation. The
// admin handler is responsible for parsing the HTTP body into this shape;
// the service decides whether the resulting client is well-formed.
type CreateClientInput struct {
	// ClientID is the operator-chosen identifier. Required, 3-100 chars,
	// lowercased + trimmed before persist (so case differences can't
	// produce phantom-duplicate rows).
	ClientID string

	// Name is the human-readable label shown in admin dashboards.
	// Required, 1-200 chars.
	Name string

	// Description is free-form notes about what the client is for.
	// Optional, ≤2000 chars.
	Description string

	// Scopes is the permission catalog the client may assert in issued
	// tokens. Empty is allowed and means "no scopes" (a sometimes-useful
	// authenticate-only configuration).
	Scopes []string

	// AllowedAudiences optionally restricts which audiences the issued
	// tokens may target. Empty means the server's default audience.
	AllowedAudiences []string

	// CreatedBy is the acting admin's user id, for audit. Optional —
	// nil is allowed (e.g. CLI bootstrap of the very first client).
	CreatedBy *types.ID
}

// Validate is the input precondition check called by the handler before
// any DB write. Centralised here so a CLI / programmatic caller gets the
// same validation as the HTTP path.
func (in *CreateClientInput) Validate() error {
	in.ClientID = strings.TrimSpace(strings.ToLower(in.ClientID))
	if in.ClientID == "" {
		return errors.InvalidInput("client_id", "client_id is required")
	}
	if len(in.ClientID) < 3 || len(in.ClientID) > 100 {
		return errors.InvalidInput("client_id", "client_id must be 3-100 chars")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return errors.InvalidInput("name", "name is required")
	}
	if len(in.Name) > 200 {
		return errors.InvalidInput("name", "name must be ≤200 chars")
	}
	if len(in.Description) > 2000 {
		return errors.InvalidInput("description", "description must be ≤2000 chars")
	}
	return nil
}

// CreateClientResult is what the handler returns to the admin. The
// plaintext ClientSecret appears here exactly once — never persisted,
// never recoverable. The admin must capture it on creation; loss
// requires rotation (delete + recreate).
type CreateClientResult struct {
	Client       *domain.M2MClient
	ClientSecret string
}

// CreateClient generates a fresh client_secret, bcrypt-hashes it, persists
// the row, and returns the plaintext secret + the row for the caller.
//
// The secret is 48 random bytes URL-base64-encoded (=64 chars) — high
// entropy, copy-paste friendly, no ambiguous characters.
func (s *M2MService) CreateClient(ctx context.Context, in CreateClientInput) (*CreateClientResult, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}

	plaintext, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, err
	}
	hash, err := utils.HashPassword(plaintext, s.bcryptCost)
	if err != nil {
		return nil, err
	}

	c := &domain.M2MClient{
		BaseModel:        models.NewBaseModel(),
		ClientID:         in.ClientID,
		ClientSecretHash: hash,
		Name:             in.Name,
		Description:      in.Description,
		Scopes:           pq.StringArray(in.Scopes),
		AllowedAudiences: pq.StringArray(in.AllowedAudiences),
		Status:           "active",
		CreatedBy:        in.CreatedBy,
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, err
	}
	return &CreateClientResult{Client: c, ClientSecret: plaintext}, nil
}

// List returns every non-revoked client, ordered newest-first.
func (s *M2MService) List(ctx context.Context) ([]*domain.M2MClient, error) {
	return s.repo.List(ctx)
}

// GetByID resolves a client by primary key — admin paths.
func (s *M2MService) GetByID(ctx context.Context, id types.ID) (*domain.M2MClient, error) {
	return s.repo.GetByID(ctx, id)
}

// Revoke soft-revokes a client. Idempotent — calling twice succeeds with
// no observable difference (the second call is a no-op SQL update).
func (s *M2MService) Revoke(ctx context.Context, id types.ID) error {
	return s.repo.Revoke(ctx, id)
}

// IssueTokenInput is the parsed RFC 6749 §4.4 client_credentials body.
type IssueTokenInput struct {
	ClientID     string
	ClientSecret string

	// Scope is the optional space-separated scope request. Parsed at the
	// handler edge; an empty slice means "grant the client's full
	// configured scopes" per RFC 6749 §3.3.
	Scopes []string
}

// IssueToken authenticates a client_credentials grant and mints a
// service-principal access token.
//
// Security:
//   - Constant-time NotFound on every failure mode (missing client,
//     wrong secret, disabled, revoked). The repo-level GetByClientID
//     filters revoked rows already; we add disabled-status + secret-
//     mismatch into the same error envelope here.
//   - bcrypt verify on the secret hash (CPU-bound by design — bounds
//     online brute force).
//   - LastUsedAt is stamped after issuance; failure to stamp does NOT
//     fail the grant (the token is already minted; bookkeeping only).
//   - Scope intersection: EffectiveScopes() in the domain layer drops
//     out-of-bounds scope requests silently per RFC 6749 §3.3 — the
//     client cannot escalate beyond its catalog.
//
// Returns the same NotFound shape for missing / wrong-secret / disabled
// so a caller cannot distinguish them by error message or timing window.
func (s *M2MService) IssueToken(ctx context.Context, in IssueTokenInput) (*jwt.ServiceTokenResponse, error) {
	if in.ClientID == "" || in.ClientSecret == "" {
		return nil, errors.InvalidInput("client_id", "client_id and client_secret are required")
	}

	client, err := s.repo.GetByClientID(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}

	// Active-status check before bcrypt verify keeps the disabled path as
	// cheap as the not-found path (both return the same NotFound; bcrypt
	// is the expensive bit). subtle.ConstantTimeCompare wouldn't help
	// here — bcrypt is the comparator and it's already constant-time on
	// the hash side.
	if !client.IsActive() {
		return nil, errors.NotFound("m2m_client")
	}

	if !utils.CheckPassword(in.ClientSecret, client.ClientSecretHash) {
		return nil, errors.NotFound("m2m_client")
	}

	// Belt + suspenders: even if CheckPassword somehow returns true on an
	// empty hash, the subtle compare on the trimmed ClientID guards against
	// a degenerate empty-string-secret config.
	if subtle.ConstantTimeCompare([]byte(client.ClientID), []byte(strings.TrimSpace(in.ClientID))) != 1 {
		return nil, errors.NotFound("m2m_client")
	}

	scopes := client.EffectiveScopes(in.Scopes)

	tok, err := s.jwt.GenerateServiceToken(ctx, client, scopes)
	if err != nil {
		return nil, err
	}

	// Fire-and-forget bookkeeping. A failed stamp leaves last_used_at
	// stale but the token is valid — caller proceeds.
	if err := s.repo.StampLastUsed(ctx, client.ID); err != nil {
		s.log.Warn("m2m: failed to stamp last_used_at",
			"client_id", client.ClientID, "err", err)
	}

	return tok, nil
}
