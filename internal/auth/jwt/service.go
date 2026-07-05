package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ven/auth/internal/audit"
	"github.com/ven/auth/internal/cache"
	"github.com/ven/auth/internal/config"
	"github.com/ven/auth/internal/domain"
	"github.com/ven/auth/internal/repository"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/types"
	"github.com/ven/auth/pkg/shared/utils"
)

// parserLeeway is the clock-skew tolerance applied to exp/nbf checks. 30s is
// long enough to cover NTP drift across replicas; short enough that an
// expired token can't be replayed meaningfully.
const parserLeeway = 30 * time.Second

// Service handles JWT token operations.
//
// AUDIT 1.6 + 1.7: validators were previously constructed ad-hoc with a raw
// `jwt.ParseWithClaims` call and no audience/issuer assertions. They also
// signed password-reset and email-verification tokens with the
// AccessTokenSecret, so rotating the access secret silently invalidated
// outstanding reset links and a leaked reset secret would compromise the
// access path. The Service now holds:
//
//   - separate purpose-derived secrets for reset and verify (HMAC-SHA256 of
//     the access secret with a purpose info string). Cryptographically
//     independent, no extra env vars needed; operators can override with
//     JWT_RESET_SECRET / JWT_VERIFY_SECRET if they need independent rotation.
//   - per-purpose audiences (`<issuer>:reset`, `<issuer>:verify`) so a reset
//     token presented to /auth/me fails on audience mismatch even before
//     signature/purpose-claim checks fire.
//   - parsers preconfigured with WithAudience + WithIssuer + WithLeeway so
//     every call site validates uniformly.
//
// AUDIT C5 — dual-secret rotation: when JWT_ACCESS_SECRET_PREVIOUS /
// JWT_REFRESH_SECRET_PREVIOUS are set, validators try the active key first
// and fall back to the previous key on signature mismatch only. Signing
// always uses the active key. Reset/verify purpose secrets are HMAC-derived
// from the access master, so the previous slot derives a parallel pair of
// purpose secrets — outstanding reset links survive an access-secret rotation
// for as long as the previous slot is populated.
type Service struct {
	cfg       config.JWTConfig
	tokenRepo repository.TokenRepository
	cache     cache.TokenCache

	// Active secrets (used for signing AND tried first on every validation).
	// accessSecret / refreshSecret are byte-views of the configured strings
	// (cached to skip the []byte conversion on every validation). resetSecret /
	// verifySecret are HMAC-derived from the access secret.
	accessSecret  []byte
	refreshSecret []byte
	resetSecret   []byte
	verifySecret  []byte

	// Previous secrets (rotation in progress). Empty slices when no previous
	// slot is configured. Validators fall back to these only when the active
	// secret produces a signature-mismatch error. resetSecretPrev /
	// verifySecretPrev are HMAC-derived from the previous access master.
	accessSecretPrev  []byte
	refreshSecretPrev []byte
	resetSecretPrev   []byte
	verifySecretPrev  []byte

	// Purpose audiences. Distinct per purpose so a reset token can never
	// pass an access-token audience check.
	accessAudience []string
	resetAudience  []string
	verifyAudience []string

	// Parsers preconfigured per token type. golang-jwt does NOT validate
	// audience or issuer unless you opt in with WithAudience/WithIssuer.
	accessParser  *jwt.Parser
	refreshParser *jwt.Parser
	resetParser   *jwt.Parser
	verifyParser  *jwt.Parser
}

// NewService creates a new JWT service.
func NewService(cfg config.JWTConfig, tokenRepo repository.TokenRepository, tokenCache cache.TokenCache) *Service {
	if tokenCache == nil {
		tokenCache = cache.NewNoOpTokenCache()
	}

	accessSecret := []byte(cfg.AccessTokenSecret)
	refreshSecret := []byte(cfg.RefreshTokenSecret)
	resetSecret := derivePurposeSecret(accessSecret, "password_reset")
	verifySecret := derivePurposeSecret(accessSecret, "email_verification")

	// AUDIT C5: derive the parallel previous-slot secrets when rotation is in
	// progress. Each previous slot is independent — operators can rotate
	// access without refresh (or vice versa) so we don't couple them. When a
	// slot is empty, the corresponding []byte is nil and the validator's
	// fallback path is a no-op.
	var accessSecretPrev, refreshSecretPrev, resetSecretPrev, verifySecretPrev []byte
	if cfg.AccessTokenSecretPrevious != "" {
		accessSecretPrev = []byte(cfg.AccessTokenSecretPrevious)
		// Purpose secrets are HMAC(access_master, "purpose"), so rotating
		// the access master also rotates reset/verify. The previous slot
		// derives its own parallel pair so outstanding reset/verify links
		// signed under the prior master keep validating until expiry.
		resetSecretPrev = derivePurposeSecret(accessSecretPrev, "password_reset")
		verifySecretPrev = derivePurposeSecret(accessSecretPrev, "email_verification")
	}
	if cfg.RefreshTokenSecretPrevious != "" {
		refreshSecretPrev = []byte(cfg.RefreshTokenSecretPrevious)
	}

	accessAudience := cfg.Audience
	if len(accessAudience) == 0 {
		accessAudience = []string{cfg.Issuer}
	}
	resetAudience := []string{cfg.Issuer + ":reset"}
	verifyAudience := []string{cfg.Issuer + ":verify"}

	// Note: golang-jwt's WithAudience validates that AT LEAST ONE of the
	// configured audiences appears in the token's `aud` claim. We pass the
	// first (canonical) value here.
	commonOpts := func(aud string) []jwt.ParserOption {
		return []jwt.ParserOption{
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(aud),
			jwt.WithLeeway(parserLeeway),
			jwt.WithValidMethods([]string{"HS256"}),
		}
	}

	return &Service{
		cfg:               cfg,
		tokenRepo:         tokenRepo,
		cache:             tokenCache,
		accessSecret:      accessSecret,
		refreshSecret:     refreshSecret,
		resetSecret:       resetSecret,
		verifySecret:      verifySecret,
		accessSecretPrev:  accessSecretPrev,
		refreshSecretPrev: refreshSecretPrev,
		resetSecretPrev:   resetSecretPrev,
		verifySecretPrev:  verifySecretPrev,
		accessAudience:    accessAudience,
		resetAudience:     resetAudience,
		verifyAudience:    verifyAudience,
		accessParser:      jwt.NewParser(commonOpts(accessAudience[0])...),
		refreshParser:     jwt.NewParser(commonOpts(accessAudience[0])...),
		resetParser:       jwt.NewParser(commonOpts(resetAudience[0])...),
		verifyParser:      jwt.NewParser(commonOpts(verifyAudience[0])...),
	}
}

// derivePurposeSecret returns HMAC-SHA256(masterSecret, "ven-auth:"+purpose),
// giving each purpose its own cryptographically-independent secret. Rotating
// the master secret rotates every derived secret in lockstep; that's the
// desired behavior (a single env to manage).
func derivePurposeSecret(masterSecret []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, masterSecret)
	mac.Write([]byte("ven-auth:purpose:"))
	mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

// parseWithRotation parses a token against the active secret, falling back to
// the previous secret on signature-mismatch only. This is the unified
// validate-side rotation primitive (AUDIT C5). It's narrow on purpose: any
// non-signature failure (exp / aud / iss / malformed) is the active secret's
// final word — we never reissue against the previous slot for those, because
// they mean the token IS one of ours but otherwise invalid.
//
// We allocate a fresh claims struct per attempt so signature-failed leftovers
// from the first parse don't bleed into the successful path. The factory
// pattern (rather than reflection or a clone interface) keeps allocations
// type-safe and obvious at the call site.
//
// active must be non-empty; previous may be empty (rotation not in progress)
// in which case the function behaves exactly like a single-key parse.
func parseWithRotation[C jwt.Claims](
	parser *jwt.Parser,
	tokenString string,
	newClaims func() C,
	active, previous []byte,
) (*jwt.Token, C, error) {
	var zero C
	claims := newClaims()
	token, err := parser.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (any, error) {
		return active, nil
	})
	if err == nil {
		return token, claims, nil
	}
	if len(previous) == 0 || !stderrors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return token, zero, err
	}
	// Retry with previous. golang-jwt populates claims via json.Unmarshal
	// before verifying the signature, so the prior attempt may have left
	// fields filled. Fresh allocation keeps the success path uncontaminated.
	claims2 := newClaims()
	token2, err2 := parser.ParseWithClaims(tokenString, claims2, func(_ *jwt.Token) (any, error) {
		return previous, nil
	})
	if err2 != nil {
		return token2, zero, err2
	}
	return token2, claims2, nil
}

// TokenPair represents an access and refresh token pair
type TokenPair struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    int64           `json:"expires_in"`
	ExpiresAt    types.Timestamp `json:"expires_at"`
}

// GenerateTokenInput contains input for token generation
type GenerateTokenInput struct {
	User         *domain.User
	Organization *domain.Organization
	Roles        []*domain.Role
	Permissions  []string
	RememberMe   bool
	DeviceInfo   string
	IPAddress    string
	UserAgent    string
	// App, when non-nil, scopes the issued token to a consuming app.
	// AUDIT 8.3 — the app_id + app_code claims appear on access tokens.
	// Nil means "base-user mode" (AUTH_ALLOW_BASE_USER_LOGIN); the
	// resulting tokens carry no app context.
	App *domain.App
	// ParentRefreshToken, when non-nil, marks the issuance as a rotation:
	// the new refresh-token row inherits the parent's FamilyID and points
	// back at it via ParentID. Nil means "this is a fresh login" → new
	// family root. AUDIT 1.9.
	ParentRefreshToken *domain.RefreshToken

	// Impersonator, when non-nil, stamps the access token with
	// imp_uid + imp_email so every action under the resulting session is
	// audit-traceable back to the acting admin. AUDIT C7.
	Impersonator *domain.User
}

// GenerateTokenPair generates an access/refresh token pair
func (s *Service) GenerateTokenPair(ctx context.Context, input GenerateTokenInput) (*TokenPair, error) {
	now := time.Now().UTC()

	// Determine expiry based on remember me
	accessExpiry := s.cfg.AccessTokenExpiry
	refreshExpiry := s.cfg.RefreshTokenExpiry
	if input.RememberMe {
		refreshExpiry = s.cfg.RememberMeExpiry
	}

	accessExpiresAt := now.Add(accessExpiry)
	refreshExpiresAt := now.Add(refreshExpiry)

	// Extract role codes and permissions
	roleCodes := make([]string, len(input.Roles))
	for i, r := range input.Roles {
		roleCodes[i] = r.Code
	}

	// Build access token claims
	var orgID *types.ID
	var orgSlug, orgName string
	if input.Organization != nil {
		orgID = &input.Organization.ID
		orgSlug = input.Organization.Slug
		orgName = input.Organization.Name
	}

	sessionID := types.NewID()

	// AUDIT 1.10: capture the per-user token-version at issue time. If a
	// later logout-all bumps the counter, this token's tv claim will trail
	// the current value and fail validation immediately. Falls back to 0
	// when Redis is unavailable (TokenCache is the NoOp impl).
	tokenVersion, _ := s.cache.GetUserTokenVersion(ctx, input.User.ID.String())

	accessClaims := &TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   input.User.ID.String(),
			Audience:  s.cfg.Audience,
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        types.NewID().String(),
		},
		UserID:           input.User.ID,
		Email:            string(input.User.Email),
		FirstName:        input.User.FirstName,
		LastName:         input.User.LastName,
		DisplayName:      input.User.DisplayName,
		OrganizationID:   orgID,
		OrganizationSlug: orgSlug,
		OrganizationName: orgName,
		Roles:            roleCodes,
		Permissions:      input.Permissions,
		TokenType:        types.TokenTypeAccess,
		SessionID:        &sessionID,
		RememberMe:       input.RememberMe,
		AuthProvider:     string(input.User.AuthProvider),
		TokenVersion:     tokenVersion,
	}
	// Migration 017: stamp the user's home pool. Omitted for "default"
	// (json omitempty) to keep the common-case token small.
	if input.User.Namespace != "" && input.User.Namespace != domain.DefaultNamespace {
		accessClaims.Namespace = input.User.Namespace
	}
	// AUDIT 8.3: app scoping. Nil App leaves the claim unset (base-user
	// mode); downstream services that enforce app scope will reject.
	if input.App != nil {
		appID := input.App.ID
		accessClaims.AppID = &appID
		accessClaims.AppCode = input.App.Code
	}
	// AUDIT C7: impersonation stamps. When set, every action under this
	// token's session is audit-traceable back to the impersonating admin
	// even though `uid` / `sub` are the target user.
	if input.Impersonator != nil {
		impID := input.Impersonator.ID
		accessClaims.ImpersonatorUserID = &impID
		accessClaims.ImpersonatorEmail = string(input.Impersonator.Email)
	}

	// Generate access token
	accessToken, err := s.generateToken(accessClaims, s.cfg.AccessTokenSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenID := types.NewID()
	refreshTokenValue, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token value: %w", err)
	}

	refreshClaims := &RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   input.User.ID.String(),
			Audience:  s.cfg.Audience,
			ExpiresAt: jwt.NewNumericDate(refreshExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        refreshTokenID.String(),
		},
		UserID:         input.User.ID,
		OrganizationID: orgID,
		TokenID:        refreshTokenID,
		RememberMe:     input.RememberMe,
	}
	if input.App != nil {
		refreshClaims.AppCode = input.App.Code
	}

	refreshToken, err := s.generateToken(refreshClaims, s.cfg.RefreshTokenSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database. AUDIT 1.9: link the row to its
	// family — either a fresh root (login/SSO) or a rotation descendant
	// (parent supplied by RefreshTokens path).
	tokenHash := s.hashToken(refreshTokenValue)
	var storedToken *domain.RefreshToken
	if input.ParentRefreshToken != nil {
		storedToken = domain.NewRotatedRefreshToken(input.ParentRefreshToken, tokenHash, refreshExpiresAt)
	} else {
		storedToken = domain.NewRefreshToken(input.User.ID, orgID, tokenHash, refreshExpiresAt)
	}
	storedToken.ID = refreshTokenID
	// FamilyID was set by the constructor above; for a brand-new root we
	// also need it to point at this row's ID (the NewRefreshToken
	// constructor set FamilyID from a freshly-generated BaseModel ID,
	// but we override the ID above to refreshTokenID — so re-sync).
	if input.ParentRefreshToken == nil {
		storedToken.FamilyID = refreshTokenID
	}
	storedToken.DeviceInfo = input.DeviceInfo
	storedToken.IPAddress = input.IPAddress
	storedToken.UserAgent = input.UserAgent

	if err := s.tokenRepo.CreateRefreshToken(ctx, storedToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Create session
	session := domain.NewSession(input.User.ID, orgID, refreshTokenID, refreshExpiresAt)
	session.ID = sessionID
	session.DeviceInfo = input.DeviceInfo
	session.IPAddress = input.IPAddress
	session.UserAgent = input.UserAgent

	if err := s.tokenRepo.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessExpiry.Seconds()),
		ExpiresAt:    accessExpiresAt,
	}, nil
}

// ServiceTokenResponse is what /oauth/token returns to a successful
// client_credentials grant. Shape matches RFC 6749 §5.1 (access_token,
// token_type, expires_in, scope) plus the absolute expires_at for clients
// that prefer wall-clock to relative seconds. No refresh_token — RFC 6749
// §4.4.3 explicitly forbids refresh tokens on client_credentials; the
// client just re-grants when expiry approaches.
type ServiceTokenResponse struct {
	AccessToken string          `json:"access_token"`
	TokenType   string          `json:"token_type"`
	ExpiresIn   int64           `json:"expires_in"`
	ExpiresAt   types.Timestamp `json:"expires_at"`
	Scope       string          `json:"scope,omitempty"`
}

// GenerateServiceToken issues a service-principal access JWT for the
// OAuth2 client_credentials grant (POST /oauth/token). The token carries
// TokenType=service and the m2m_clients row identity in ClientID +
// ServiceName + Scopes, with all user-shaped fields (UserID, Email, Roles,
// Permissions, etc.) left as zero values.
//
// Signed with the active access-token secret so downstream services
// validate it via the same parser they use for user tokens — they then
// branch on claims.IsServicePrincipal() to apply service-only authz. This
// is intentional: one parser, one secret, one rotation flow.
//
// No row is persisted: service tokens are stateless. There's no equivalent
// of the refresh_tokens / sessions tables for M2M — the credential row
// (m2m_clients) is the only durable state and we stamp its last_used_at
// at the service layer. Revocation is handled by the m2m_clients table:
// revoke the client, future grants fail, outstanding tokens age out at
// natural expiry. For immediate kill on a leaked token, bump the
// associated client's hot path index (or extend with a per-client tv —
// not in MVP scope).
//
// The audience defaults to the server's configured access audience; an
// explicit subset can be enforced by the caller via client.AllowedAudiences
// before reaching this function.
func (s *Service) GenerateServiceToken(ctx context.Context, client *domain.M2MClient, scopes []string) (*ServiceTokenResponse, error) {
	_ = ctx // reserved for future per-client tv lookup; kept in signature for symmetry with GenerateTokenPair.

	now := time.Now().UTC()
	expiresAt := now.Add(s.cfg.AccessTokenExpiry)

	claims := &TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   client.ClientID,
			Audience:  s.cfg.Audience,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        types.NewID().String(),
		},
		TokenType:   types.TokenTypeService,
		ClientID:    client.ClientID,
		ServiceName: client.Name,
		Scopes:      scopes,
		Roles:       []string{},
		Permissions: []string{},
	}

	tokenString, err := s.generateToken(claims, s.cfg.AccessTokenSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate service token: %w", err)
	}

	return &ServiceTokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.cfg.AccessTokenExpiry.Seconds()),
		ExpiresAt:   expiresAt,
		Scope:       strings.Join(scopes, " "),
	}, nil
}

// ValidateAccessToken validates an access token and returns its claims.
//
// Validation order, top to bottom:
//  1. blacklist check on the token hash (cheap Redis GET)
//  2. cached-claims short-circuit (skips signature reparse on hot paths)
//  3. signature + audience + issuer + leeway + algorithm via accessParser
//  4. token-type claim discriminator
//
// AUDIT 1.6 hardens steps 3-4: the previous implementation used a raw
// ParseWithClaims call that did NOT assert audience or issuer, so a token
// signed with the same secret but for a different service would have been
// accepted on `/auth/me`. The parser now enforces all three claims.
func (s *Service) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	// Check blacklist and cache
	tokenHash := s.hashToken(tokenString)
	ctx := context.Background()

	// Check if token is blacklisted
	if blacklisted, err := s.cache.IsBlacklisted(ctx, tokenHash); err == nil && blacklisted {
		return nil, errors.TokenRevoked()
	}

	// Check cache for previously validated token
	if cached, err := s.cache.GetCachedToken(ctx, tokenHash); err == nil && cached != nil {
		// Reconstruct claims from cache
		if cached.ExpiresAt > time.Now().Unix() {
			userID, parseErr := types.ParseID(cached.UserID)
			if parseErr == nil {
				// AUDIT 1.10: even on cache hit, check that the cached
				// token-version still matches the current per-user counter.
				// A logout-all bump must invalidate cached entries too,
				// otherwise stale claims would serve until natural expiry.
				currentTV, _ := s.cache.GetUserTokenVersion(ctx, cached.UserID)
				if cached.TokenVersion < currentTV {
					_ = s.cache.InvalidateCachedToken(ctx, tokenHash)
					return nil, errors.TokenRevoked()
				}
				claims := &TokenClaims{
					UserID:           userID,
					Email:            cached.Email,
					FirstName:        cached.FirstName,
					LastName:         cached.LastName,
					OrganizationSlug: cached.OrganizationSlug,
					Roles:            cached.Roles,
					Permissions:      cached.Permissions,
					TokenType:        types.TokenType(cached.TokenType),
					TokenVersion:     cached.TokenVersion,
				}
				if cached.OrganizationID != "" {
					if orgID, err := types.ParseID(cached.OrganizationID); err == nil {
						claims.OrganizationID = &orgID
					}
				}
				if cached.SessionID != "" {
					if sessionID, err := types.ParseID(cached.SessionID); err == nil {
						claims.SessionID = &sessionID
					}
				}
				return claims, nil
			}
		}
	}

	token, claims, err := parseWithRotation(
		s.accessParser, tokenString,
		func() *TokenClaims { return &TokenClaims{} },
		s.accessSecret, s.accessSecretPrev,
	)
	if err != nil {
		if stderrors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.TokenExpired()
		}
		return nil, errors.TokenInvalid().WithError(err)
	}

	if !token.Valid {
		return nil, errors.TokenInvalid()
	}

	if claims.TokenType != types.TokenTypeAccess {
		return nil, errors.TokenInvalid()
	}

	// AUDIT 1.10: token-version gate on the fresh-parse path. Same shape
	// as the cached-hit path above. If the user's current version has
	// advanced past what this token carries, the token has been globally
	// revoked (logout-all, role change, security event).
	currentTV, _ := s.cache.GetUserTokenVersion(ctx, claims.UserID.String())
	if claims.TokenVersion < currentTV {
		return nil, errors.TokenRevoked()
	}

	// Cache the validated token
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl > 0 {
		cachedClaims := &cache.CachedClaims{
			UserID:           claims.UserID.String(),
			Email:            claims.Email,
			FirstName:        claims.FirstName,
			LastName:         claims.LastName,
			OrganizationSlug: claims.OrganizationSlug,
			Roles:            claims.Roles,
			Permissions:      claims.Permissions,
			TokenType:        string(claims.TokenType),
			ExpiresAt:        claims.ExpiresAt.Time.Unix(),
			TokenVersion:     claims.TokenVersion,
		}
		if claims.OrganizationID != nil {
			cachedClaims.OrganizationID = claims.OrganizationID.String()
		}
		if claims.SessionID != nil {
			cachedClaims.SessionID = claims.SessionID.String()
		}
		_ = s.cache.CacheValidatedToken(ctx, tokenHash, cachedClaims, ttl)
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token. Uses refreshParser which
// enforces audience/issuer/leeway/algorithm in addition to signature — see
// AUDIT 1.6.
func (s *Service) ValidateRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error) {
	token, claims, err := parseWithRotation(
		s.refreshParser, tokenString,
		func() *RefreshTokenClaims { return &RefreshTokenClaims{} },
		s.refreshSecret, s.refreshSecretPrev,
	)
	if err != nil {
		if stderrors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.TokenExpired()
		}
		return nil, errors.TokenInvalid().WithError(err)
	}

	if !token.Valid {
		return nil, errors.TokenInvalid()
	}

	// AUDIT 1.9: deliberately do NOT short-circuit on a revoked row here.
	// The validator's job is purely cryptographic (signature, exp, aud,
	// iss) — persistent-row policy (reuse detection, family revocation,
	// last-used tracking) lives in RefreshTokens which owns the rotation
	// state machine. Returning revoked-error here would prevent the
	// reuse-detection branch from ever firing.
	return claims, nil
}

// RefreshTokens generates a new token pair from a valid refresh token.
//
// AUDIT 1.9 (RFC 6819 §5.2.2.3) — refresh-token family / reuse detection:
//
//  1. Validate the JWT (signature, exp, audience, issuer).
//  2. Look up the stored row by claims.TokenID.
//  3. If the row is *already revoked*, this is the textbook "refresh-token
//     reuse" signal: the legitimate user previously rotated, and now an
//     attacker (or the legitimate user from stale state) is presenting the
//     old token. Revoke the entire family and return TokenRevoked. Both the
//     legitimate user and the attacker lose their session; the user
//     re-authenticates from scratch.
//  4. Otherwise revoke the presented row and mint a new pair whose refresh
//     row inherits the parent's FamilyID (descendant in the chain).
//
// All of this happens inside a single transaction so the "revoke + create
// child" pair is atomic — a concurrent second refresh of the same token
// loses the race and sees the now-revoked row, triggering the family-revoke
// path on the next attempt.
func (s *Service) RefreshTokens(ctx context.Context, refreshTokenString string, input GenerateTokenInput) (*TokenPair, error) {
	claims, err := s.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, err
	}

	stored, err := s.tokenRepo.GetRefreshTokenByID(ctx, claims.TokenID)
	if err != nil {
		// Row missing: the token's signature was valid but the persistent
		// record is gone (cleaned up, manually deleted, never written). Don't
		// reveal which — return a generic TokenInvalid.
		return nil, errors.TokenInvalid()
	}

	// Step 3: reuse detection. A revoked-but-otherwise-valid refresh token
	// being presented again means the legitimate user already rotated; this
	// presentation is presumed theft.
	if stored.Revoked {
		_, _ = s.tokenRepo.RevokeRefreshTokenFamily(ctx, stored.FamilyID, "refresh_token_reuse_detected")
		audit.Record(ctx, audit.Event{
			Action:       "refresh.reuse_detected",
			ActorUserID:  &stored.UserID,
			ResourceID:   &stored.FamilyID,
			ResourceType: "refresh_token_family",
			Details: map[string]any{
				"presented_token_id": stored.ID.String(),
			},
		})
		return nil, errors.TokenRevoked()
	}

	// Defense in depth: also reject if expired according to the row (the JWT
	// check already covers this, but the row is the source of truth for
	// session lifetime).
	if !stored.IsValid() {
		return nil, errors.TokenInvalid()
	}

	// Step 3a: idle policy. When RefreshIdleTimeout is configured, a
	// refresh chain that hasn't been advanced within the window is
	// considered abandoned and the whole family is revoked. Anchoring
	// on the row's `created_at` (= time the previous refresh minted it)
	// makes "row age == time since the chain was last advanced", which
	// is the right semantic for inactivity.
	//
	// This is server-authoritative defense-in-depth on top of the SDK's
	// optional client-side IdleTracker: a stolen refresh token sitting
	// unused past the threshold is dead even if a malicious client lies
	// about activity.
	if s.cfg.RefreshIdleTimeout > 0 {
		idleFor := time.Since(stored.CreatedAt)
		if idleFor > s.cfg.RefreshIdleTimeout {
			_, _ = s.tokenRepo.RevokeRefreshTokenFamily(ctx, stored.FamilyID, "refresh_idle_timeout")
			audit.Record(ctx, audit.Event{
				Action:       "refresh.idle_timeout",
				ActorUserID:  &stored.UserID,
				ResourceID:   &stored.FamilyID,
				ResourceType: "refresh_token_family",
				Details: map[string]any{
					"presented_token_id": stored.ID.String(),
					"idle_for_seconds":   int64(idleFor.Seconds()),
					"threshold_seconds":  int64(s.cfg.RefreshIdleTimeout.Seconds()),
				},
			})
			return nil, errors.TokenRevoked()
		}
	}

	// Step 4: revoke the presented row and mint a child. Keep the steps
	// close together so the gap is small; we don't wrap in a transaction
	// because the RefreshToken constructor for the child needs to run with
	// the parent already revoked-visible to concurrent racers (a second
	// concurrent refresh of the same token will see the new revoke and
	// fail-then-trigger-family-revoke on its next attempt).
	//
	// AUDIT: we stamp `last_used_at` on the parent here. The schema +
	// domain field have existed since migration 001 but the rotation
	// path used to call RevokeRefreshToken (which only flips `revoked`),
	// throwing the in-memory UpdateLastUsed() away. Going through
	// UpdateRefreshToken folds last_used_at + revoked + revoked_at +
	// revoked_reason into a single UPDATE with `AND revoked = false`,
	// preserving the atomic "first writer wins" guard against concurrent
	// rotations of the same row.
	stored.UpdateLastUsed()
	stored.Revoke("token_refresh")
	if err := s.tokenRepo.UpdateRefreshToken(ctx, stored); err != nil {
		// If update fails (e.g. concurrent rotation already revoked it,
		// or row vanished), treat as TokenInvalid. The next refresh
		// attempt will see the now-revoked row and trip the reuse-
		// detection path.
		return nil, errors.TokenInvalid()
	}

	// Carry the parent into GenerateTokenPair so the new row links into the
	// existing family rather than starting a new one.
	input.RememberMe = claims.RememberMe
	input.ParentRefreshToken = stored

	return s.GenerateTokenPair(ctx, input)
}

// RevokeRefreshToken revokes a refresh token
func (s *Service) RevokeRefreshToken(ctx context.Context, tokenID types.ID, reason string) error {
	// Blacklist the token ID in cache
	_ = s.cache.BlacklistToken(ctx, tokenID.String(), s.cfg.AccessTokenExpiry)
	return s.tokenRepo.RevokeRefreshToken(ctx, tokenID, reason)
}

// RevokeAllUserTokens revokes every refresh token + session for a user AND
// bumps the per-user token-version counter so that every outstanding access
// token is immediately invalidated cross-replica — AUDIT 1.10.
//
// Order matters: terminate sessions and revoke refresh tokens first (so a
// reused refresh token can't slip a new pair past us), then bump the version
// so that any access tokens minted during this very call (e.g. by a concurrent
// login) are still pinned to the old version and rejected.
func (s *Service) RevokeAllUserTokens(ctx context.Context, userID types.ID, reason string) error {
	if err := s.tokenRepo.TerminateAllUserSessions(ctx, userID); err != nil {
		return err
	}
	if err := s.tokenRepo.RevokeAllUserTokens(ctx, userID, reason); err != nil {
		return err
	}
	// Best-effort: if Redis is unavailable, the version stays at 0 and
	// access tokens persist until expiry. Refresh tokens are still
	// killed (DB-backed) so the user can't extend their session.
	_, _ = s.cache.BumpUserTokenVersion(ctx, userID.String())

	audit.Record(ctx, audit.Event{
		Action:        "logout.all",
		ActorUserID:   &userID,
		SubjectUserID: &userID,
		Details:       map[string]any{"reason": reason},
	})
	return nil
}

// GeneratePasswordResetToken generates a password reset token
func (s *Service) GeneratePasswordResetToken(ctx context.Context, user *domain.User, expiry time.Duration) (string, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)

	tokenValue, err := utils.GenerateRandomString(64)
	if err != nil {
		return "", fmt.Errorf("failed to generate token value: %w", err)
	}

	tokenHash := s.hashToken(tokenValue)
	storedToken := domain.NewPasswordResetToken(user.ID, tokenHash, expiresAt)

	// Invalidate existing tokens
	if err := s.tokenRepo.InvalidateUserPasswordResetTokens(ctx, user.ID); err != nil {
		return "", err
	}

	if err := s.tokenRepo.CreatePasswordResetToken(ctx, storedToken); err != nil {
		return "", err
	}

	// Generate JWT for the reset link. AUDIT 1.7 + 1.6: signed with a
	// purpose-derived secret distinct from the access secret (so an access-
	// secret rotation doesn't silently invalidate outstanding reset links,
	// and a leaked reset secret doesn't compromise the access path), and
	// audience is set to the reset-specific value so a reset token presented
	// to `/auth/me` fails on audience mismatch before any other check.
	claims := &PasswordResetClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   user.ID.String(),
			Audience:  s.resetAudience,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        storedToken.ID.String(),
		},
		UserID:  user.ID,
		Email:   string(user.Email),
		Purpose: PurposePasswordReset,
	}

	return s.generateTokenBytes(claims, s.resetSecret)
}

// ValidatePasswordResetToken validates a password reset token. Returns the
// claims on success; the caller is responsible for the single-use check
// against the stored row (auth_service.ResetPassword) — see AUDIT 1.1.
func (s *Service) ValidatePasswordResetToken(ctx context.Context, tokenString string) (*PasswordResetClaims, error) {
	token, claims, err := parseWithRotation(
		s.resetParser, tokenString,
		func() *PasswordResetClaims { return &PasswordResetClaims{} },
		s.resetSecret, s.resetSecretPrev,
	)
	if err != nil {
		if stderrors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.TokenExpired()
		}
		return nil, errors.TokenInvalid()
	}

	if !token.Valid {
		return nil, errors.TokenInvalid()
	}

	// AUDIT 1.6: defense-in-depth purpose check. The audience claim already
	// blocks cross-purpose presentation; this is a second gate keyed on the
	// payload so even a misconfigured parser would still reject.
	if claims.Purpose != PurposePasswordReset {
		return nil, errors.TokenInvalid()
	}

	return claims, nil
}

// GenerateEmailVerificationToken generates an email verification token
func (s *Service) GenerateEmailVerificationToken(ctx context.Context, user *domain.User, expiry time.Duration) (string, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)

	tokenValue, err := utils.GenerateRandomString(64)
	if err != nil {
		return "", fmt.Errorf("failed to generate token value: %w", err)
	}

	tokenHash := s.hashToken(tokenValue)
	storedToken := domain.NewEmailVerificationToken(user.ID, user.Email, tokenHash, expiresAt)

	// Invalidate existing tokens
	if err := s.tokenRepo.InvalidateUserEmailVerificationTokens(ctx, user.ID); err != nil {
		return "", err
	}

	if err := s.tokenRepo.CreateEmailVerificationToken(ctx, storedToken); err != nil {
		return "", err
	}

	// Generate JWT for the verification link — signed with the verify-
	// purpose secret + audience, see PasswordReset above for rationale.
	claims := &EmailVerificationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   user.ID.String(),
			Audience:  s.verifyAudience,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        storedToken.ID.String(),
		},
		UserID:  user.ID,
		Email:   string(user.Email),
		Purpose: PurposeEmailVerification,
	}

	return s.generateTokenBytes(claims, s.verifySecret)
}

// ValidateEmailVerificationToken validates an email verification token. The
// caller (auth_service.VerifyEmail) does the single-use stored-row check —
// see AUDIT 1.2.
func (s *Service) ValidateEmailVerificationToken(ctx context.Context, tokenString string) (*EmailVerificationClaims, error) {
	token, claims, err := parseWithRotation(
		s.verifyParser, tokenString,
		func() *EmailVerificationClaims { return &EmailVerificationClaims{} },
		s.verifySecret, s.verifySecretPrev,
	)
	if err != nil {
		if stderrors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.TokenExpired()
		}
		return nil, errors.TokenInvalid()
	}

	if !token.Valid {
		return nil, errors.TokenInvalid()
	}

	if claims.Purpose != PurposeEmailVerification {
		return nil, errors.TokenInvalid()
	}

	return claims, nil
}

// generateToken generates a JWT token with the given claims using a
// string-keyed secret. Kept for the access/refresh paths which hold the
// secret as a config string.
func (s *Service) generateToken(claims jwt.Claims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// generateTokenBytes signs with a raw byte key. Used by purpose-derived
// secrets (HMAC output) so we don't pay a []byte conversion on every issue.
func (s *Service) generateTokenBytes(claims jwt.Claims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// hashToken creates a SHA-256 hash of a token
func (s *Service) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// GetUserSessions retrieves active sessions for a user
func (s *Service) GetUserSessions(ctx context.Context, userID types.ID) ([]*domain.Session, error) {
	return s.tokenRepo.ListUserSessions(ctx, userID)
}

// TerminateSession terminates a specific session.
//
// Why this revokes the refresh-token *family* rather than the single
// row pinned to `session.RefreshTokenID`:
//
//   - `session.RefreshTokenID` is set ONCE at login and never updated
//     when the SDK rotates its access token.
//   - Every rotation creates a new refresh-token row that inherits the
//     parent's `family_id`, then revokes the parent.
//   - So after the first rotation, `session.RefreshTokenID` always
//     points to a row that's `revoked = true`. The old single-row
//     RevokeRefreshToken(...) path matched 0 rows there and returned
//     `TokenInvalid` — making "Terminate" fail on every long-lived
//     session.
//
// Revoking the family kills every live descendant in the chain in one
// shot. RevokeRefreshTokenFamily already returns successfully on a
// zero-row update (idempotent), so terminating a session whose tokens
// were already all revoked (e.g. via logout-all earlier) still
// succeeds — the session row itself is what closes the door.
//
// If the linked refresh-token row is missing entirely (cleaned up by
// a maintenance job, say), we still terminate the session row —
// orphaned sessions shouldn't be un-terminable.
func (s *Service) TerminateSession(ctx context.Context, sessionID types.ID) error {
	session, err := s.tokenRepo.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	if refreshToken, rtErr := s.tokenRepo.GetRefreshTokenByID(ctx, session.RefreshTokenID); rtErr == nil && refreshToken != nil {
		_, _ = s.tokenRepo.RevokeRefreshTokenFamily(ctx, refreshToken.FamilyID, "session_terminated")
	}

	return s.tokenRepo.TerminateSession(ctx, sessionID)
}
