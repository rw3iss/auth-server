package sso

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ven/auth/internal/config"
	"github.com/ven/auth/pkg/shared/types"
)

func TestFacebookGetUserInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok123" {
			t.Errorf("missing/wrong bearer: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"fb-1","email":"jane@x.com","first_name":"Jane","last_name":"Doe"}`))
	}))
	defer srv.Close()

	p := NewFacebookProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a", ClientSecret: "b"})
	p.userInfoURL = srv.URL

	ui, err := p.GetUserInfo(t.Context(), "tok123")
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if ui.ProviderUserID != "fb-1" || ui.Email != "jane@x.com" || ui.Provider != types.AuthProviderFacebook {
		t.Fatalf("unexpected user info: %+v", ui)
	}
	if !ui.EmailVerified {
		t.Error("FB-returned email should be treated as verified")
	}
	if ui.FirstName != "Jane" || ui.LastName != "Doe" {
		t.Errorf("name mismatch: %q %q", ui.FirstName, ui.LastName)
	}
}

func TestFacebookGetUserInfo_NoEmail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Phone-registered FB user: no email field.
		_, _ = w.Write([]byte(`{"id":"fb-2","first_name":"Phone","last_name":"Only"}`))
	}))
	defer srv.Close()

	p := NewFacebookProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a", ClientSecret: "b"})
	p.userInfoURL = srv.URL

	ui, err := p.GetUserInfo(t.Context(), "tok")
	if err != nil {
		t.Fatalf("no-email FB login must not error: %v", err)
	}
	if ui.ProviderUserID != "fb-2" {
		t.Fatalf("provider id mismatch: %q", ui.ProviderUserID)
	}
	if ui.Email != "" || ui.EmailVerified {
		t.Errorf("expected empty/unverified email, got %q verified=%v", ui.Email, ui.EmailVerified)
	}
}

func TestLinkedInGetUserInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"li-1","email":"li@x.com","email_verified":true,"given_name":"Lee","family_name":"Kim","name":"Lee Kim"}`))
	}))
	defer srv.Close()

	p := NewLinkedInProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a", ClientSecret: "b"})
	p.userInfoURL = srv.URL

	ui, err := p.GetUserInfo(t.Context(), "tok")
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if ui.ProviderUserID != "li-1" || ui.Email != "li@x.com" || !ui.EmailVerified {
		t.Fatalf("unexpected: %+v", ui)
	}
	if ui.FirstName != "Lee" || ui.LastName != "Kim" || ui.Provider != types.AuthProviderLinkedIn {
		t.Fatalf("field mismatch: %+v", ui)
	}
}

func TestProvidersEnabledGuard(t *testing.T) {
	off := NewFacebookProvider(config.OAuthProviderConfig{Enabled: false})
	if off.IsEnabled() {
		t.Error("disabled facebook should not be enabled")
	}
	noSecret := NewLinkedInProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a"})
	if noSecret.IsEnabled() {
		t.Error("linkedin without client secret should not be enabled")
	}
}
