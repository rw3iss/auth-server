package sso

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rw3iss/auth/internal/config"
	"github.com/rw3iss/auth/pkg/shared/types"
)

func newTestXProvider(cfg config.OAuthProviderConfig) *XProvider {
	p := NewXProvider(cfg)
	return p
}

func TestXGetUserInfo_NoEmailSynthesizesPlaceholder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok123" {
			t.Errorf("missing/wrong bearer: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"x-42","name":"Jane Doe","username":"janedoe","profile_image_url":"https://pbs.twimg.com/profile_images/1/abc_normal.jpg","verified":true}}`))
	}))
	defer srv.Close()

	p := newTestXProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a", ClientSecret: "b"})
	p.userInfoURL = srv.URL

	ui, err := p.GetUserInfo(t.Context(), "tok123")
	if err != nil {
		t.Fatalf("GetUserInfo must not error on missing email: %v", err)
	}
	if ui.ProviderUserID != "x-42" {
		t.Fatalf("provider id mismatch: %q", ui.ProviderUserID)
	}
	if ui.Email != "x-x-42@users.x.invalid" {
		t.Errorf("expected synthesized placeholder email, got %q", ui.Email)
	}
	if ui.EmailVerified {
		t.Error("placeholder email must not be marked verified")
	}
	if ui.DisplayName != "Jane Doe" || ui.FirstName != "Jane Doe" {
		t.Errorf("name mismatch: display=%q first=%q", ui.DisplayName, ui.FirstName)
	}
	if ui.AvatarURL != "https://pbs.twimg.com/profile_images/1/abc_400x400.jpg" {
		t.Errorf("avatar should upgrade _normal -> _400x400, got %q", ui.AvatarURL)
	}
	if ui.RawData["username"] != "janedoe" {
		t.Errorf("username should be surfaced in RawData, got %v", ui.RawData["username"])
	}
	if ui.Provider != types.AuthProviderX {
		t.Errorf("provider mismatch: %v", ui.Provider)
	}
}

func TestXGetUserInfo_MissingIDErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"name":"No Id"}}`))
	}))
	defer srv.Close()

	p := newTestXProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a", ClientSecret: "b"})
	p.userInfoURL = srv.URL

	if _, err := p.GetUserInfo(t.Context(), "tok"); err == nil {
		t.Fatal("expected error when profile has no id")
	}
}

func TestXBuildAuthURLWithPKCE(t *testing.T) {
	p := newTestXProvider(config.OAuthProviderConfig{
		Enabled:  true,
		ClientID: "cid",
		Scopes:   []string{"tweet.read", "users.read", "offline.access"},
	})
	raw := p.BuildAuthURLWithPKCE("state-xyz", "https://civicgate.org/auth/callback", "CHALLENGE123")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("bad url: %v", err)
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type: %q", q.Get("response_type"))
	}
	if q.Get("client_id") != "cid" {
		t.Errorf("client_id: %q", q.Get("client_id"))
	}
	if q.Get("code_challenge") != "CHALLENGE123" {
		t.Errorf("code_challenge: %q", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method: %q", q.Get("code_challenge_method"))
	}
	if q.Get("state") != "state-xyz" {
		t.Errorf("state: %q", q.Get("state"))
	}
	if q.Get("scope") != "tweet.read users.read offline.access" {
		t.Errorf("scope: %q", q.Get("scope"))
	}
	if q.Get("redirect_uri") != "https://civicgate.org/auth/callback" {
		t.Errorf("redirect_uri: %q", q.Get("redirect_uri"))
	}
}

func TestXExchangeCodeWithVerifier_SendsBasicAuthAndVerifier(t *testing.T) {
	var gotAuth, gotVerifier, gotGrant, gotCode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(b))
		gotVerifier = vals.Get("code_verifier")
		gotGrant = vals.Get("grant_type")
		gotCode = vals.Get("code")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","refresh_token":"RT","token_type":"bearer","expires_in":7200,"scope":"tweet.read"}`))
	}))
	defer srv.Close()

	p := newTestXProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "cid", ClientSecret: "sec"})
	p.tokenURL = srv.URL

	resp, err := p.ExchangeCodeWithVerifier(t.Context(), "the-code", "https://cb", "the-verifier")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:sec"))
	if gotAuth != wantAuth {
		t.Errorf("basic auth header mismatch: got %q want %q", gotAuth, wantAuth)
	}
	if gotVerifier != "the-verifier" {
		t.Errorf("code_verifier not sent: %q", gotVerifier)
	}
	if gotGrant != "authorization_code" {
		t.Errorf("grant_type: %q", gotGrant)
	}
	if gotCode != "the-code" {
		t.Errorf("code: %q", gotCode)
	}
	if resp.AccessToken != "AT" || resp.RefreshToken != "RT" {
		t.Errorf("token response mismatch: %+v", resp)
	}
}

func TestXExchangeCodePlainIsRejected(t *testing.T) {
	p := newTestXProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a", ClientSecret: "b"})
	if _, err := p.ExchangeCode(t.Context(), "code", "https://cb"); err == nil {
		t.Fatal("plain ExchangeCode must be rejected for X (PKCE required)")
	}
}

func TestXValidateIDTokenUnsupported(t *testing.T) {
	p := newTestXProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a", ClientSecret: "b"})
	if _, err := p.ValidateIDToken(t.Context(), "anything"); err == nil {
		t.Fatal("X issues no id_token; ValidateIDToken must error")
	}
}

func TestXEnabledGuard(t *testing.T) {
	if NewXProvider(config.OAuthProviderConfig{Enabled: false}).IsEnabled() {
		t.Error("disabled X should not be enabled")
	}
	if NewXProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a"}).IsEnabled() {
		t.Error("X without client secret should not be enabled")
	}
	if !NewXProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "a", ClientSecret: "b"}).IsEnabled() {
		t.Error("X with id+secret should be enabled")
	}
}

func TestXManagerRoutesPKCE(t *testing.T) {
	// End-to-end-ish: the manager should generate a verifier, embed a challenge
	// on the auth URL, and store the verifier in the state record so the
	// callback can reunite it with the exchange.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(b))
		if vals.Get("code_verifier") == "" {
			t.Error("callback exchange did not carry the code_verifier from state")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","token_type":"bearer","expires_in":7200}`))
	}))
	defer tokenSrv.Close()
	userSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"x-9","name":"Nine","username":"nine"}}`))
	}))
	defer userSrv.Close()

	xp := NewXProvider(config.OAuthProviderConfig{Enabled: true, ClientID: "cid", ClientSecret: "sec"})
	xp.tokenURL = tokenSrv.URL
	xp.userInfoURL = userSrv.URL

	m := &Manager{
		providers:     map[types.AuthProvider]Provider{types.AuthProviderX: xp},
		stateStore:    NewInMemoryStateStore(t.Context()),
		authCodeStore: NewInMemoryAuthCodeStore(t.Context()),
	}

	authURL, state, err := m.GetAuthURL(t.Context(), AuthURLInput{
		Provider:    types.AuthProviderX,
		RedirectURL: "https://cb",
	})
	if err != nil {
		t.Fatalf("GetAuthURL: %v", err)
	}
	if !strings.Contains(authURL, "code_challenge=") || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("auth URL missing PKCE challenge: %s", authURL)
	}

	ui, _, err := m.HandleCallback(t.Context(), state, "auth-code")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if ui.ProviderUserID != "x-9" || ui.Email != "x-x-9@users.x.invalid" {
		t.Fatalf("unexpected user info: %+v", ui)
	}
}
