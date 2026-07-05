package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/ven/auth/internal/audit"
	"github.com/ven/auth/internal/auth/jwt"
	"github.com/ven/auth/internal/domain"
	"github.com/ven/auth/internal/repository"
	"github.com/ven/auth/internal/service"
	sharederr "github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
	"github.com/ven/auth/pkg/shared/utils"
)

// MagicLinkService implements the magic-link sign-in flow.
//
// Request side (`Request`):
//   - Normalises the email, looks up the user. If the email isn't
//     registered we silently no-op and return success — never reveal
//     whether an email is in the system.
//   - Mints a 32-byte random token, stores its SHA-256 hash, and emails
//     the bare token to the user.
//   - Failed email sends are logged but DON'T fail the request — the
//     anti-enumeration property would otherwise leak.
//
// Verify side (`Verify`):
//   - Hashes the incoming token, looks up the row, applies all the
//     "is this still usable?" checks (not consumed, not expired).
//   - Stamps `consumed_at` BEFORE issuing tokens so a race-double-submit
//     can't redeem the same token twice.
//   - Issues a normal token-pair via the JWT service — exactly the
//     shape /auth/login returns. Caller treats it as a login.
//
// We deliberately don't reuse the email-verification table: their
// lifecycles overlap (a user may have both an unverified email and an
// outstanding magic-link), and the verification flow flips the user's
// `email_verified` bit which we don't want here.
type MagicLinkService struct {
	db        *sqlx.DB
	userRepo  repository.UserRepository
	roleRepo  repository.RoleRepository
	tokenRepo repository.TokenRepository
	jwtSvc    *jwt.Service
	email     service.EmailService
	// appResolver mirrors the lookup AuthService uses to map app_code →
	// app row + auto-grant. Injecting the live AppService keeps the
	// behavior aligned across login and magic-link.
	appService AppDirectory
	ttl        time.Duration
}

// NewMagicLinkService wires the service with everything it needs.
func NewMagicLinkService(
	db *sqlx.DB,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	tokenRepo repository.TokenRepository,
	jwtSvc *jwt.Service,
	email service.EmailService,
	appService AppDirectory,
) *MagicLinkService {
	return &MagicLinkService{
		db:         db,
		userRepo:   userRepo,
		roleRepo:   roleRepo,
		tokenRepo:  tokenRepo,
		jwtSvc:     jwtSvc,
		email:      email,
		appService: appService,
		ttl:        15 * time.Minute,
	}
}

// RequestInput is the input shape for /auth/magic-link/request.
type MagicLinkRequestInput struct {
	Email     string
	AppCode   string
	IPAddress string
	UserAgent string
}

// Request mints + emails a magic-link. Always returns nil unless the
// caller passed a malformed email; never leaks user existence.
func (s *MagicLinkService) Request(ctx context.Context, in MagicLinkRequestInput) error {
	email := types.Email(utils.NormalizeEmail(in.Email))
	if !utils.IsValidEmail(string(email)) {
		return sharederr.InvalidInput("email", "Invalid email format")
	}

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		// Constant-time-ish no-op — log audit so legitimate admins can
		// see request frequency for anti-enumeration metrics.
		audit.Record(ctx, audit.Event{
			Action:  "magic_link.request_unknown",
			Details: map[string]any{"email": string(email)},
		})
		return nil
	}

	token, err := utils.GenerateRandomString(48)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	const q = `
		INSERT INTO magic_links
			(user_id, email, token_hash, app_code, expires_at, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = s.db.ExecContext(ctx, q,
		user.ID, string(email), tokenHash, in.AppCode,
		time.Now().Add(s.ttl), in.IPAddress, in.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("insert magic_link: %w", err)
	}

	// Resolve the requesting app's frontend URL so the magic-link
	// lands inside the same app the user initiated the request from.
	// Empty when AppCode wasn't supplied or doesn't resolve — the
	// email layer falls back to CLIENT_URL in that case.
	var appBase string
	if in.AppCode != "" && s.appService != nil {
		if app, err := s.appService.GetByCode(ctx, in.AppCode); err == nil && app != nil && app.IsActive() {
			appBase = app.FrontendBaseURL()
		}
	}

	if err := s.email.SendMagicLinkEmail(ctx, appBase, string(email), user.FirstName, token); err != nil {
		// Log but don't fail — refusing leaks user existence.
		audit.Record(ctx, audit.Event{
			Action:        "magic_link.email_failed",
			ActorUserID:   &user.ID,
			SubjectUserID: &user.ID,
			Details:       map[string]any{"email": string(email), "error": err.Error()},
		})
	}
	audit.Record(ctx, audit.Event{
		Action:        "magic_link.requested",
		ActorUserID:   &user.ID,
		SubjectUserID: &user.ID,
		Details:       map[string]any{"email": string(email)},
	})
	return nil
}

// Verify exchanges a magic-link token for an access/refresh pair.
//
// Three failure modes, all returning the same TokenInvalid error so a
// caller can't distinguish them: unknown token, already consumed, expired.
func (s *MagicLinkService) Verify(ctx context.Context, token, ipAddress, userAgent string) (*LoginResult, error) {
	if token == "" {
		return nil, sharederr.TokenInvalid()
	}
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	type linkRow struct {
		ID         types.ID       `db:"id"`
		UserID     types.ID       `db:"user_id"`
		AppCode    sql.NullString `db:"app_code"`
		ExpiresAt  time.Time      `db:"expires_at"`
		ConsumedAt sql.NullTime   `db:"consumed_at"`
	}

	var link linkRow
	err := s.db.GetContext(ctx, &link,
		`SELECT id, user_id, app_code, expires_at, consumed_at
		   FROM magic_links WHERE token_hash = $1`,
		tokenHash,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sharederr.TokenInvalid()
		}
		return nil, fmt.Errorf("lookup magic_link: %w", err)
	}
	if link.ConsumedAt.Valid {
		return nil, sharederr.TokenInvalid()
	}
	if time.Now().After(link.ExpiresAt) {
		return nil, sharederr.TokenInvalid()
	}

	// Stamp consumed BEFORE issuing tokens — a parallel verify of the
	// same token will see consumed_at set and reject. UPDATE returns the
	// number of affected rows so a race where both requests hit the
	// table simultaneously results in exactly one winning consumer.
	res, err := s.db.ExecContext(ctx,
		`UPDATE magic_links SET consumed_at = NOW()
		   WHERE id = $1 AND consumed_at IS NULL`,
		link.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("consume magic_link: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return nil, sharederr.TokenInvalid()
	}

	user, err := s.userRepo.GetByID(ctx, link.UserID)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	if user.Status == types.UserStatusSuspended || user.DeletedAt != nil {
		return nil, sharederr.UserSuspended()
	}

	// Token generation mirrors AuthService.Login — same shape, same
	// claims, same expiry. Roles + permissions are loaded fresh.
	roles, err := s.userRepo.GetBaseRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("load base roles: %w", err)
	}
	permissions := collectRolePermissions(roles)

	tokenInput := jwt.GenerateTokenInput{
		User:        user,
		Roles:       roles,
		Permissions: permissions,
		DeviceInfo:  userAgent,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
	}
	if link.AppCode.Valid && link.AppCode.String != "" && s.appService != nil {
		if app, err := s.appService.GetByCode(ctx, link.AppCode.String); err == nil && app != nil && app.IsActive() {
			tokenInput.App = app
		}
	}
	pair, err := s.jwtSvc.GenerateTokenPair(ctx, tokenInput)
	if err != nil {
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	// Stamp last-login. Same hygiene as AuthService.Login.
	now := types.Now()
	user.LastLoginAt = &now
	_ = s.userRepo.Update(ctx, user)

	audit.Record(ctx, audit.Event{
		Action:        "magic_link.consumed",
		ActorUserID:   &user.ID,
		SubjectUserID: &user.ID,
		Details:       map[string]any{"email": string(user.Email)},
	})

	return &LoginResult{
		User:      user,
		TokenPair: pair,
	}, nil
}

// collectRolePermissions flattens roles' Permissions slices, de-duping.
// Mirrors AuthService.collectPermissions but doesn't depend on a repo
// lookup — magic-link doesn't need cross-role resolution since
// userRepo.GetBaseRoles already hydrates Permissions on each role.
func collectRolePermissions(roles []*domain.Role) []string {
	seen := map[string]bool{}
	out := make([]string, 0)
	for _, r := range roles {
		for _, p := range r.Permissions {
			if !seen[p.Code] {
				seen[p.Code] = true
				out = append(out, p.Code)
			}
		}
	}
	return out
}
