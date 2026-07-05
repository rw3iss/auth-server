package jwt

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/ven/auth/internal/cache"
	"github.com/ven/auth/internal/config"
	"github.com/ven/auth/internal/domain"
	"github.com/ven/auth/internal/repository"
	"github.com/ven/auth/pkg/shared/types"
)

// stubTokenRepo records the rows the JWT service tries to write so tests can
// assert without needing a real Postgres connection. Only the methods that
// the validators actually invoke are implemented; the rest are no-ops.
type stubTokenRepo struct {
	resetTokens   map[string]*domain.PasswordResetToken
	verifyTokens  map[string]*domain.EmailVerificationToken
	refreshTokens map[string]*domain.RefreshToken
	familyRevokes []string // family_ids that were revoked, in order
}

func newStubTokenRepo() *stubTokenRepo {
	return &stubTokenRepo{
		resetTokens:   map[string]*domain.PasswordResetToken{},
		verifyTokens:  map[string]*domain.EmailVerificationToken{},
		refreshTokens: map[string]*domain.RefreshToken{},
	}
}

func (s *stubTokenRepo) CreateRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	s.refreshTokens[t.ID.String()] = t
	return nil
}
func (s *stubTokenRepo) GetRefreshToken(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	for _, t := range s.refreshTokens {
		if t.TokenHash == hash {
			return t, nil
		}
	}
	return nil, nil
}
func (s *stubTokenRepo) GetRefreshTokenByID(ctx context.Context, id types.ID) (*domain.RefreshToken, error) {
	if t, ok := s.refreshTokens[id.String()]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("not found")
}
func (s *stubTokenRepo) UpdateRefreshToken(ctx context.Context, t *domain.RefreshToken) error {
	s.refreshTokens[t.ID.String()] = t
	return nil
}
func (s *stubTokenRepo) RevokeRefreshToken(ctx context.Context, id types.ID, reason string) error {
	if t, ok := s.refreshTokens[id.String()]; ok {
		t.Revoke(reason)
	}
	return nil
}
func (s *stubTokenRepo) RevokeRefreshTokenFamily(ctx context.Context, familyID types.ID, reason string) (int, error) {
	n := 0
	for _, t := range s.refreshTokens {
		if t.FamilyID == familyID && !t.Revoked {
			t.Revoke(reason)
			n++
		}
	}
	s.familyRevokes = append(s.familyRevokes, familyID.String())
	return n, nil
}
func (s *stubTokenRepo) RevokeAllUserTokens(ctx context.Context, userID types.ID, reason string) error {
	return nil
}
func (s *stubTokenRepo) RevokeUserOrgTokens(ctx context.Context, userID, orgID types.ID, reason string) error {
	return nil
}
func (s *stubTokenRepo) ListUserRefreshTokens(ctx context.Context, userID types.ID) ([]*domain.RefreshToken, error) {
	return nil, nil
}
func (s *stubTokenRepo) CleanupExpiredTokens(ctx context.Context) (int, error) { return 0, nil }

func (s *stubTokenRepo) CreatePasswordResetToken(ctx context.Context, t *domain.PasswordResetToken) error {
	s.resetTokens[t.ID.String()] = t
	return nil
}
func (s *stubTokenRepo) GetPasswordResetToken(ctx context.Context, hash string) (*domain.PasswordResetToken, error) {
	return nil, nil
}
func (s *stubTokenRepo) GetPasswordResetTokenByID(ctx context.Context, id types.ID) (*domain.PasswordResetToken, error) {
	return s.resetTokens[id.String()], nil
}
func (s *stubTokenRepo) MarkPasswordResetTokenUsed(ctx context.Context, id types.ID) error {
	if t, ok := s.resetTokens[id.String()]; ok {
		t.Used = true
	}
	return nil
}
func (s *stubTokenRepo) InvalidateUserPasswordResetTokens(ctx context.Context, userID types.ID) error {
	return nil
}

func (s *stubTokenRepo) CreateEmailVerificationToken(ctx context.Context, t *domain.EmailVerificationToken) error {
	s.verifyTokens[t.ID.String()] = t
	return nil
}
func (s *stubTokenRepo) GetEmailVerificationToken(ctx context.Context, hash string) (*domain.EmailVerificationToken, error) {
	return nil, nil
}
func (s *stubTokenRepo) GetEmailVerificationTokenByID(ctx context.Context, id types.ID) (*domain.EmailVerificationToken, error) {
	return s.verifyTokens[id.String()], nil
}
func (s *stubTokenRepo) MarkEmailVerificationTokenUsed(ctx context.Context, id types.ID) error {
	if t, ok := s.verifyTokens[id.String()]; ok {
		t.Used = true
	}
	return nil
}
func (s *stubTokenRepo) InvalidateUserEmailVerificationTokens(ctx context.Context, userID types.ID) error {
	return nil
}

func (s *stubTokenRepo) CreateSession(ctx context.Context, sess *domain.Session) error { return nil }
func (s *stubTokenRepo) GetSession(ctx context.Context, id types.ID) (*domain.Session, error) {
	return nil, nil
}
func (s *stubTokenRepo) UpdateSession(ctx context.Context, sess *domain.Session) error { return nil }
func (s *stubTokenRepo) TerminateSession(ctx context.Context, id types.ID) error       { return nil }
func (s *stubTokenRepo) TerminateAllUserSessions(ctx context.Context, userID types.ID) error {
	return nil
}
func (s *stubTokenRepo) ListUserSessions(ctx context.Context, userID types.ID) ([]*domain.Session, error) {
	return nil, nil
}

var _ repository.TokenRepository = (*stubTokenRepo)(nil)

// memCache is an in-memory TokenCache that actually tracks the per-user
// token-version counter — needed to verify AUDIT 1.10 behavior end-to-end.
// (NoOpTokenCache always reports version=0, so the version gate is a no-op
// against it.)
type memCache struct {
	versions map[string]int64
}

func newMemCache() *memCache {
	return &memCache{versions: map[string]int64{}}
}

func (m *memCache) CacheValidatedToken(_ context.Context, _ string, _ *cache.CachedClaims, _ time.Duration) error {
	return nil
}
func (m *memCache) GetCachedToken(_ context.Context, _ string) (*cache.CachedClaims, error) {
	return nil, nil
}
func (m *memCache) InvalidateCachedToken(_ context.Context, _ string) error { return nil }
func (m *memCache) BlacklistToken(_ context.Context, _ string, _ time.Duration) error {
	return nil
}
func (m *memCache) IsBlacklisted(_ context.Context, _ string) (bool, error) { return false, nil }
func (m *memCache) IncrementRateLimit(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, nil
}
func (m *memCache) IncrementAccountAttempts(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, nil
}
func (m *memCache) ResetAccountAttempts(_ context.Context, _ string) error { return nil }
func (m *memCache) GetUserTokenVersion(_ context.Context, userID string) (int64, error) {
	return m.versions[userID], nil
}
func (m *memCache) BumpUserTokenVersion(_ context.Context, userID string) (int64, error) {
	m.versions[userID]++
	return m.versions[userID], nil
}

var _ cache.TokenCache = (*memCache)(nil)

func testService(t *testing.T) (*Service, *stubTokenRepo) {
	t.Helper()
	repo := newStubTokenRepo()
	svc := NewService(config.JWTConfig{
		AccessTokenSecret:  "test-access-secret-32-characters-min-len-padded",
		RefreshTokenSecret: "test-refresh-secret-32-characters-min-len-padded",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		Issuer:             "ven-auth-test",
		Audience:           []string{"ven-platform-test"},
		SigningMethod:      "HS256",
	}, repo, cache.NewNoOpTokenCache())
	return svc, repo
}

// testServiceWithMemCache returns a service whose TokenCache tracks the
// per-user version counter, so AUDIT 1.10 behavior can be exercised.
func testServiceWithMemCache(t *testing.T) (*Service, *stubTokenRepo, *memCache) {
	t.Helper()
	repo := newStubTokenRepo()
	mc := newMemCache()
	svc := NewService(config.JWTConfig{
		AccessTokenSecret:  "test-access-secret-32-characters-min-len-padded",
		RefreshTokenSecret: "test-refresh-secret-32-characters-min-len-padded",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		Issuer:             "ven-auth-test",
		Audience:           []string{"ven-platform-test"},
		SigningMethod:      "HS256",
	}, repo, mc)
	return svc, repo, mc
}

func newTestUser(t *testing.T) *domain.User {
	t.Helper()
	return domain.NewUser(types.Email("user@example.com"), "Test", "User")
}

// AUDIT 1.1: A password-reset JWT validates fine, but the second presentation
// must be rejected because the row is marked used. The JWT itself remains
// signature-valid until expiry — single-use enforcement lives at the row.
func TestPasswordResetTokenValidatesAndRowTracksUsed(t *testing.T) {
	svc, repo := testService(t)
	user := newTestUser(t)
	ctx := context.Background()

	tokenStr, err := svc.GeneratePasswordResetToken(ctx, user, time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	claims, err := svc.ValidatePasswordResetToken(ctx, tokenStr)
	if err != nil {
		t.Fatalf("validate first time: %v", err)
	}
	if claims.Purpose != PurposePasswordReset {
		t.Fatalf("expected purpose=%q, got %q", PurposePasswordReset, claims.Purpose)
	}
	id, err := types.ParseID(claims.ID)
	if err != nil {
		t.Fatalf("claims.ID parse: %v", err)
	}
	if _, ok := repo.resetTokens[id.String()]; !ok {
		t.Fatalf("expected stored row with id %s", id)
	}
	// Caller marks used; second validation of the JWT is still cryptographically
	// valid — single-use lives at the row check in auth_service.
	if err := repo.MarkPasswordResetTokenUsed(ctx, id); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	if !repo.resetTokens[id.String()].Used {
		t.Fatal("expected row.Used=true after MarkPasswordResetTokenUsed")
	}
}

// AUDIT 1.6: a token signed under the access secret with the wrong audience
// must be rejected by the access validator (audience guard).
func TestValidateAccessTokenRejectsWrongAudience(t *testing.T) {
	svc, _ := testService(t)
	now := time.Now().UTC()
	user := newTestUser(t)
	claims := &TokenClaims{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    "ven-auth-test",
			Subject:   user.ID.String(),
			Audience:  []string{"someone-elses-audience"},
			ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  gjwt.NewNumericDate(now),
			NotBefore: gjwt.NewNumericDate(now),
			ID:        types.NewID().String(),
		},
		UserID:    user.ID,
		Email:     string(user.Email),
		TokenType: types.TokenTypeAccess,
	}
	tokenStr, err := svc.generateToken(claims, "test-access-secret-32-characters-min-len-padded")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := svc.ValidateAccessToken(tokenStr); err == nil {
		t.Fatal("expected audience-mismatch rejection")
	}
}

// AUDIT 1.6: a token signed by a different issuer with our secret must fail.
func TestValidateAccessTokenRejectsWrongIssuer(t *testing.T) {
	svc, _ := testService(t)
	now := time.Now().UTC()
	user := newTestUser(t)
	claims := &TokenClaims{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    "someone-elses-issuer",
			Subject:   user.ID.String(),
			Audience:  []string{"ven-platform-test"},
			ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  gjwt.NewNumericDate(now),
			NotBefore: gjwt.NewNumericDate(now),
			ID:        types.NewID().String(),
		},
		UserID:    user.ID,
		TokenType: types.TokenTypeAccess,
	}
	tokenStr, err := svc.generateToken(claims, "test-access-secret-32-characters-min-len-padded")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := svc.ValidateAccessToken(tokenStr); err == nil {
		t.Fatal("expected issuer-mismatch rejection")
	}
}

// AUDIT 1.7: password-reset tokens are signed with a purpose-derived secret
// (HMAC of access secret) — they must NOT validate as access tokens, even
// though the access secret is the master input.
func TestPasswordResetTokenCannotBePresentedAsAccessToken(t *testing.T) {
	svc, _ := testService(t)
	user := newTestUser(t)
	ctx := context.Background()

	resetStr, err := svc.GeneratePasswordResetToken(ctx, user, time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := svc.ValidateAccessToken(resetStr); err == nil {
		t.Fatal("expected reset-as-access to fail (different secret + audience)")
	}
}

// AUDIT 1.6: an email-verification token presented to the reset validator
// must fail. Same secret family (both derived from access master), but
// distinct purpose claim, audience, and derived secret.
func TestEmailVerificationTokenRejectedByPasswordResetValidator(t *testing.T) {
	svc, _ := testService(t)
	user := newTestUser(t)
	ctx := context.Background()

	verifyStr, err := svc.GenerateEmailVerificationToken(ctx, user, time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := svc.ValidatePasswordResetToken(ctx, verifyStr); err == nil {
		t.Fatal("expected cross-purpose rejection")
	}
}

// AUDIT 1.9: a successful rotation preserves the parent's FamilyID on the
// new row and links back via ParentID.
func TestRefreshTokenRotationPreservesFamily(t *testing.T) {
	svc, repo := testService(t)
	user := newTestUser(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("initial pair: %v", err)
	}

	// Find the stored row by reverse-looking-up via the JWT we just minted.
	claims, err := svc.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("validate initial: %v", err)
	}
	parent := repo.refreshTokens[claims.TokenID.String()]
	if parent == nil {
		t.Fatal("initial refresh row not stored")
	}
	if parent.FamilyID != parent.ID {
		t.Fatalf("root family_id should equal id, got family=%s id=%s", parent.FamilyID, parent.ID)
	}
	if parent.ParentID != nil {
		t.Fatal("root parent_id should be nil")
	}

	pair2, err := svc.RefreshTokens(ctx, pair.RefreshToken, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	claims2, err := svc.ValidateRefreshToken(ctx, pair2.RefreshToken)
	if err != nil {
		t.Fatalf("validate rotated: %v", err)
	}
	child := repo.refreshTokens[claims2.TokenID.String()]
	if child == nil {
		t.Fatal("rotated row not stored")
	}
	if child.FamilyID != parent.FamilyID {
		t.Fatalf("child family should match parent: child=%s parent=%s", child.FamilyID, parent.FamilyID)
	}
	if child.ParentID == nil || *child.ParentID != parent.ID {
		t.Fatalf("child.ParentID should point at parent.ID: got %v", child.ParentID)
	}
	if !parent.Revoked {
		t.Fatal("parent should be revoked after rotation")
	}
}

// AUDIT 1.9 / RFC 6819 §5.2.2.3: presenting an already-rotated refresh token
// must revoke the entire family — the legitimate user and the presumed
// attacker both lose access.
func TestRefreshTokenReuseRevokesEntireFamily(t *testing.T) {
	svc, repo := testService(t)
	user := newTestUser(t)
	ctx := context.Background()

	// Build a chain of three rotations: root → A → B → C.
	root, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	a, err := svc.RefreshTokens(ctx, root.RefreshToken, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("rotate A: %v", err)
	}
	b, err := svc.RefreshTokens(ctx, a.RefreshToken, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("rotate B: %v", err)
	}
	_ = b

	// Attacker presents the long-revoked root token. This must trip the
	// reuse-detection branch and revoke every row in the family.
	if _, err := svc.RefreshTokens(ctx, root.RefreshToken, GenerateTokenInput{User: user}); err == nil {
		t.Fatal("expected TokenRevoked on reused root")
	}

	// The family-revoke should have been recorded against the root's
	// family_id (which equals root.ID).
	if len(repo.familyRevokes) != 1 {
		t.Fatalf("expected exactly one family-revoke call, got %d (%v)", len(repo.familyRevokes), repo.familyRevokes)
	}

	// Every row in that family must now be revoked, including child B (the
	// only previously-live descendant).
	live := 0
	for _, tok := range repo.refreshTokens {
		if !tok.Revoked {
			live++
		}
	}
	if live != 0 {
		t.Fatalf("expected 0 live tokens after family revoke, got %d", live)
	}

	// Bonus: the live child B's refresh token must now fail when presented
	// — proves the attacker can't quietly continue the chain.
	if _, err := svc.RefreshTokens(ctx, b.RefreshToken, GenerateTokenInput{User: user}); err == nil {
		t.Fatal("expected B's refresh to fail after family revoke")
	}
}

// Rotation must stamp last_used_at on the parent row. Pre-fix the
// rotation called RevokeRefreshToken (which only flips `revoked`), so
// the in-memory UpdateLastUsed() was thrown away and the column stayed
// NULL forever — making audit + idle-policy impossible.
func TestRefreshRotationStampsLastUsedOnParent(t *testing.T) {
	svc, repo := testService(t)
	user := newTestUser(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("initial pair: %v", err)
	}
	parentClaims, err := svc.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	before := time.Now()
	if _, err := svc.RefreshTokens(ctx, pair.RefreshToken, GenerateTokenInput{User: user}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	parent := repo.refreshTokens[parentClaims.TokenID.String()]
	if parent == nil {
		t.Fatal("parent row missing")
	}
	if parent.LastUsedAt == nil {
		t.Fatal("parent.LastUsedAt should be set after rotation")
	}
	if (*parent.LastUsedAt).Before(before) {
		t.Fatalf("LastUsedAt %v should be >= rotation start %v", *parent.LastUsedAt, before)
	}
	if !parent.Revoked || parent.RevokedReason == nil || *parent.RevokedReason != "token_refresh" {
		t.Fatalf("parent should be revoked with reason 'token_refresh', got revoked=%v reason=%v", parent.Revoked, parent.RevokedReason)
	}
}

// RefreshIdleTimeout > 0 + a stored row whose created_at is past the
// threshold → the presentation is rejected AND the whole family is
// revoked. Same blast radius as theft detection: idle past the policy
// window kills every live refresh row, so no other tab / device can
// silently continue the chain.
func TestRefreshIdleTimeoutRevokesFamily(t *testing.T) {
	svc, repo := testServiceWithIdleTimeout(t, 10*time.Minute)
	user := newTestUser(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("initial pair: %v", err)
	}
	parentClaims, err := svc.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	parent := repo.refreshTokens[parentClaims.TokenID.String()]

	// Backdate created_at to 30 minutes ago — well past the 10m threshold.
	parent.CreatedAt = time.Now().Add(-30 * time.Minute)

	_, err = svc.RefreshTokens(ctx, pair.RefreshToken, GenerateTokenInput{User: user})
	if err == nil {
		t.Fatal("expected TokenRevoked from idle timeout, got nil")
	}
	if len(repo.familyRevokes) != 1 {
		t.Fatalf("expected one family revoke (idle), got %d (%v)", len(repo.familyRevokes), repo.familyRevokes)
	}
	if !parent.Revoked {
		t.Fatal("parent should be revoked after idle timeout")
	}
}

// Within-window refreshes must still rotate normally; the idle config
// shouldn't interfere with active users.
func TestRefreshIdleTimeoutAllowsActiveRefresh(t *testing.T) {
	svc, _ := testServiceWithIdleTimeout(t, 10*time.Minute)
	user := newTestUser(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("initial pair: %v", err)
	}
	if _, err := svc.RefreshTokens(ctx, pair.RefreshToken, GenerateTokenInput{User: user}); err != nil {
		t.Fatalf("active rotate should succeed, got %v", err)
	}
}

func testServiceWithIdleTimeout(t *testing.T, idle time.Duration) (*Service, *stubTokenRepo) {
	t.Helper()
	repo := newStubTokenRepo()
	svc := NewService(config.JWTConfig{
		AccessTokenSecret:  "test-access-secret-32-characters-min-len-padded",
		RefreshTokenSecret: "test-refresh-secret-32-characters-min-len-padded",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		RefreshIdleTimeout: idle,
		Issuer:             "ven-auth-test",
		Audience:           []string{"ven-platform-test"},
		SigningMethod:      "HS256",
	}, repo, cache.NewNoOpTokenCache())
	return svc, repo
}

// AUDIT 1.10: a previously-valid access token must stop validating as soon
// as the per-user token-version counter advances past what the token carries.
// This is the cross-replica logout-everywhere guarantee that the old
// blacklist-by-jti approach couldn't deliver because LogoutAll only revoked
// refresh tokens.
func TestAccessTokenVersionGate(t *testing.T) {
	svc, _, mc := testServiceWithMemCache(t)
	user := newTestUser(t)
	ctx := context.Background()

	pair, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Initial validation succeeds: token's tv (0) matches user's version (0).
	if _, err := svc.ValidateAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("initial validate: %v", err)
	}

	// Logout-all bumps the counter; the previously-issued token still has
	// tv=0 but the user's current version is now 1. Validation must fail.
	if err := svc.RevokeAllUserTokens(ctx, user.ID, "logout_all"); err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	if mc.versions[user.ID.String()] != 1 {
		t.Fatalf("expected version=1 after RevokeAllUserTokens, got %d", mc.versions[user.ID.String()])
	}
	if _, err := svc.ValidateAccessToken(pair.AccessToken); err == nil {
		t.Fatal("expected access token to fail after logout-all")
	}

	// A freshly issued token captures the new version and validates again.
	pair2, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	if _, err := svc.ValidateAccessToken(pair2.AccessToken); err != nil {
		t.Fatalf("post-revoke fresh token: %v", err)
	}
}

// rotationTestServices returns (oldSvc, newSvc): oldSvc signs under the old
// secrets only; newSvc has the new secrets active AND the old secrets in the
// previous slot. This mirrors the production rotation moment: a freshly
// rolled replica accepts both old-secret and new-secret tokens.
func rotationTestServices(t *testing.T) (oldSvc, newSvc *Service) {
	t.Helper()
	const (
		oldAccess  = "old-access-secret-32-characters-padded-test-only"
		oldRefresh = "old-refresh-secret-32-characters-padded-test-only"
		newAccess  = "new-access-secret-32-characters-padded-test-only"
		newRefresh = "new-refresh-secret-32-characters-padded-test-only"
	)
	commonOld := config.JWTConfig{
		AccessTokenSecret:  oldAccess,
		RefreshTokenSecret: oldRefresh,
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		Issuer:             "ven-auth-test",
		Audience:           []string{"ven-platform-test"},
		SigningMethod:      "HS256",
	}
	commonNew := commonOld
	commonNew.AccessTokenSecret = newAccess
	commonNew.RefreshTokenSecret = newRefresh
	commonNew.AccessTokenSecretPrevious = oldAccess
	commonNew.RefreshTokenSecretPrevious = oldRefresh

	oldSvc = NewService(commonOld, newStubTokenRepo(), cache.NewNoOpTokenCache())
	newSvc = NewService(commonNew, newStubTokenRepo(), cache.NewNoOpTokenCache())
	return
}

// AUDIT C5: access tokens issued under the previous secret must validate
// against a replica that has rotated. This is the zero-downtime guarantee:
// rolling restart never logs anyone out mid-flight.
func TestAccessTokenAcceptedFromPreviousSecretAfterRotation(t *testing.T) {
	oldSvc, newSvc := rotationTestServices(t)
	user := newTestUser(t)
	ctx := context.Background()

	// Issue under the old service (active = old secret).
	pair, err := oldSvc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("issue under old: %v", err)
	}
	// Validate against the rotated service (active = new, previous = old).
	if _, err := newSvc.ValidateAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("rotated replica should accept old-secret access token: %v", err)
	}
}

// AUDIT C5: refresh tokens — same guarantee, different secret slot.
func TestRefreshTokenAcceptedFromPreviousSecretAfterRotation(t *testing.T) {
	oldSvc, newSvc := rotationTestServices(t)
	user := newTestUser(t)
	ctx := context.Background()

	pair, err := oldSvc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := newSvc.ValidateRefreshToken(ctx, pair.RefreshToken); err != nil {
		t.Fatalf("rotated replica should accept old-secret refresh token: %v", err)
	}
}

// AUDIT C5: purpose-derived rotation. Outstanding reset / verify links must
// keep validating after an access-master rotation, because the previous slot
// derives its parallel pair of purpose secrets at boot.
func TestPasswordResetTokenAcceptedFromPreviousSecretAfterRotation(t *testing.T) {
	oldSvc, newSvc := rotationTestServices(t)
	user := newTestUser(t)
	ctx := context.Background()

	resetStr, err := oldSvc.GeneratePasswordResetToken(ctx, user, time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := newSvc.ValidatePasswordResetToken(ctx, resetStr); err != nil {
		t.Fatalf("rotated replica should accept reset token signed under old master: %v", err)
	}
}

func TestEmailVerificationTokenAcceptedFromPreviousSecretAfterRotation(t *testing.T) {
	oldSvc, newSvc := rotationTestServices(t)
	user := newTestUser(t)
	ctx := context.Background()

	verifyStr, err := oldSvc.GenerateEmailVerificationToken(ctx, user, time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := newSvc.ValidateEmailVerificationToken(ctx, verifyStr); err != nil {
		t.Fatalf("rotated replica should accept verify token signed under old master: %v", err)
	}
}

// AUDIT C5: a token signed by an unrelated third party must fail even when
// rotation is active. The fallback is bounded to the configured previous
// slot — there's no "try every key we ever saw" behavior.
func TestRotationRejectsThirdPartySecret(t *testing.T) {
	_, newSvc := rotationTestServices(t)
	user := newTestUser(t)

	// Forge a token signed under a third secret (not active, not previous).
	now := time.Now().UTC()
	claims := &TokenClaims{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    "ven-auth-test",
			Subject:   user.ID.String(),
			Audience:  []string{"ven-platform-test"},
			ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  gjwt.NewNumericDate(now),
			NotBefore: gjwt.NewNumericDate(now),
			ID:        types.NewID().String(),
		},
		UserID:    user.ID,
		Email:     string(user.Email),
		TokenType: types.TokenTypeAccess,
	}
	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims)
	forged, err := token.SignedString([]byte("attacker-controlled-secret-32-characters-padded"))
	if err != nil {
		t.Fatalf("sign forged: %v", err)
	}
	if _, err := newSvc.ValidateAccessToken(forged); err == nil {
		t.Fatal("expected forged-secret token to be rejected; rotation must not accept arbitrary keys")
	}
}

// AUDIT C5: when no previous slot is configured, validators must behave
// exactly as before — single-key parse, no silent fallback path.
func TestNoRotationConfigured_OldSecretTokenRejected(t *testing.T) {
	oldSvc, _ := rotationTestServices(t)
	// Build a fresh "post-rotation" service without populating the previous
	// slot — operator forgot to set it, or rotation has fully completed.
	freshSvc := NewService(config.JWTConfig{
		AccessTokenSecret:  "new-access-secret-32-characters-padded-test-only",
		RefreshTokenSecret: "new-refresh-secret-32-characters-padded-test-only",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		Issuer:             "ven-auth-test",
		Audience:           []string{"ven-platform-test"},
		SigningMethod:      "HS256",
	}, newStubTokenRepo(), cache.NewNoOpTokenCache())

	user := newTestUser(t)
	ctx := context.Background()
	pair, err := oldSvc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := freshSvc.ValidateAccessToken(pair.AccessToken); err == nil {
		t.Fatal("expected rejection: no previous-slot configured, old-secret token should fail")
	}
}

// AUDIT 1.7: derivePurposeSecret produces independent outputs for different
// purposes. (Defense against a "what if the HMAC label is dropped" bug.)
func TestDerivePurposeSecretIndependence(t *testing.T) {
	master := []byte("master-secret-32-characters-padded-for-test")
	reset := derivePurposeSecret(master, "password_reset")
	verify := derivePurposeSecret(master, "email_verification")
	if len(reset) != 32 || len(verify) != 32 {
		t.Fatalf("expected 32-byte outputs, got reset=%d verify=%d", len(reset), len(verify))
	}
	if strings.EqualFold(string(reset), string(verify)) {
		t.Fatal("reset and verify secrets must differ")
	}
}
