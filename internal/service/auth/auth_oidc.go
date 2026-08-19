package auth

import (
	"context"
	"fmt"

	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// IssueTokensForUser mints a token pair for a user whose identity has ALREADY been established by some
// other means — today, redeeming an OIDC authorization code.
//
// This exists because the OIDC token endpoint has a genuinely different trust path from Login: the
// password was checked earlier, at the authorize step, and the code is the proof. Reusing Login here would
// mean either re-prompting for credentials (defeating the whole point of delegated auth) or inventing a
// second credential check. Instead the caller proves possession of a single-use, PKCE-bound code and this
// issues the same tokens Login would have.
//
// It deliberately does NOT check a password, so every caller must have verified something equivalent.
func (s *AuthService) IssueTokensForUser(ctx context.Context, userID types.ID, appCode string) (*jwt.TokenPair, *domain.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("load user: %w", err)
	}
	if user == nil || !user.IsActive() {
		return nil, nil, fmt.Errorf("user is not active")
	}

	roles, err := s.userRepo.GetBaseRoles(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("load roles: %w", err)
	}

	in := jwt.GenerateTokenInput{
		User:        user,
		Roles:       roles,
		Permissions: collectRolePermissions(roles),
	}
	if appCode != "" && s.appService != nil {
		if app, err := s.appService.GetByCode(ctx, appCode); err == nil && app != nil && app.IsActive() {
			in.App = app
		}
	}

	pair, err := s.jwtService.GenerateTokenPair(ctx, in)
	if err != nil {
		return nil, nil, fmt.Errorf("issue tokens: %w", err)
	}
	now := types.Now()
	user.LastLoginAt = &now
	_ = s.userRepo.Update(ctx, user)
	return pair, user, nil
}

// GetUserByID exposes a user lookup for the OIDC userinfo/ID-token claim assembly.
func (s *AuthService) GetUserByID(ctx context.Context, userID types.ID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}
