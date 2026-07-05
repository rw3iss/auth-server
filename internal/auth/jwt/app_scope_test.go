package jwt

import (
	"context"
	"testing"

	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/models"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// A token pair minted for a consuming app must stamp app_code on BOTH the
// access and refresh claims. The refresh-side claim is what lets /auth/refresh
// re-resolve the app and re-run entitlement provisioning without the client
// re-sending the app code (regression guard for the refresh-loses-app-scope
// bug fixed in 0.6.0).
func TestTokenPairCarriesAppCodeOnRefresh(t *testing.T) {
	svc, _ := testService(t)
	ctx := context.Background()
	user := newTestUser(t)
	app := &domain.App{BaseModel: models.BaseModel{ID: types.NewID()}, Code: "globalsku"}

	pair, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user, App: app})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	refresh, err := svc.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken: %v", err)
	}
	if refresh.AppCode != "globalsku" {
		t.Fatalf("refresh app_code = %q, want %q", refresh.AppCode, "globalsku")
	}

	access, err := svc.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if access.AppCode != "globalsku" {
		t.Fatalf("access app_code = %q, want %q", access.AppCode, "globalsku")
	}
}

// A base-user pair (no app) must leave app_code unset on both tokens.
func TestTokenPairWithoutAppLeavesAppCodeEmpty(t *testing.T) {
	svc, _ := testService(t)
	ctx := context.Background()
	user := newTestUser(t)

	pair, err := svc.GenerateTokenPair(ctx, GenerateTokenInput{User: user})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	refresh, err := svc.ValidateRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken: %v", err)
	}
	if refresh.AppCode != "" {
		t.Fatalf("refresh app_code = %q, want empty", refresh.AppCode)
	}
}
