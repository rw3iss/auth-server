package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/auth/jwt"
	"github.com/rw3iss/auth/internal/auth/oidc"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// ── Test doubles ──────────────────────────────────────────────────────────────────────────────────────
//
// The handler takes FedCMStore / FedCMUsers interfaces precisely so these tests
// need no database. *oidc.Store and *auth.AuthService are the production
// implementations; nothing here re-implements identity, it only stands in for I/O.

type fakeStore struct {
	client    *oidc.Client
	consents  map[string][]string // clientID -> scopes, for one user
	deleted   []string
	saved     map[string][]string
	listErr   error
	clientErr error
}

func (f *fakeStore) GetClient(_ context.Context, clientID string) (*oidc.Client, error) {
	if f.clientErr != nil {
		return nil, f.clientErr
	}
	if f.client == nil || f.client.ClientID != clientID {
		return nil, oidc.ErrClientNotFound
	}
	return f.client, nil
}
func (f *fakeStore) GetConsent(_ context.Context, _, clientID string) ([]string, error) {
	return f.consents[clientID], nil
}
func (f *fakeStore) SaveConsent(_ context.Context, _, clientID string, scopes []string) error {
	if f.saved == nil {
		f.saved = map[string][]string{}
	}
	f.saved[clientID] = scopes
	return nil
}
func (f *fakeStore) ListConsentedClients(_ context.Context, _ string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []string{}
	for k := range f.consents {
		out = append(out, k)
	}
	return out, nil
}
func (f *fakeStore) DeleteConsent(_ context.Context, _, clientID string) error {
	f.deleted = append(f.deleted, clientID)
	return nil
}

type fakeUsers struct{ user *domain.User }

func (f *fakeUsers) GetUserByID(_ context.Context, id types.ID) (*domain.User, error) {
	if f.user == nil || f.user.ID != id {
		return nil, sql.ErrNoRows
	}
	return f.user, nil
}

func testUser(t *testing.T) *domain.User {
	t.Helper()
	u := domain.NewUser("ada@example.org", "Ada", "Lovelace")
	u.Status = types.UserStatusActive
	u.EmailVerified = true
	u.DisplayName = "ada"
	u.AvatarURL = "https://cdn.example.org/ada.png"
	return u
}

func testClient() *oidc.Client {
	return &oidc.Client{
		ClientID:      "rp-demo",
		Name:          "Demo RP",
		RedirectURIs:  pq.StringArray{"https://rp.example/callback"},
		AllowedScopes: pq.StringArray{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
		Status:        "active",
	}
}

func newTestHandler(t *testing.T, store FedCMStore, users FedCMUsers) *FedCMHandler {
	t.Helper()
	// A real KeyManager, generated into a temp dir — the tokens these tests verify
	// are signed exactly the way production signs them.
	keys, err := oidc.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("key manager: %v", err)
	}
	return NewFedCMHandler(keys, store, users, "https://auth.example.org",
		"https://www.example.org/login", DefaultFedCMBranding())
}

// withSession puts claims in the request context the way AuthenticateCookie does.
func withSession(r *http.Request, u *domain.User) *http.Request {
	claims := &jwt.TokenClaims{UserID: u.ID, Email: string(u.Email)}
	ctx := context.WithValue(r.Context(), middleware.ContextKeyClaims, claims)
	return r.WithContext(ctx)
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return out
}

// ── Discovery ─────────────────────────────────────────────────────────────────────────────────────────

func TestWellKnownPointsAtTheConfig(t *testing.T) {
	h := newTestHandler(t, &fakeStore{}, &fakeUsers{})
	w := httptest.NewRecorder()
	h.WellKnown(w, httptest.NewRequest("GET", "/.well-known/web-identity", nil))

	if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	urls, _ := decode(t, w)["provider_urls"].([]any)
	if len(urls) != 1 || urls[0] != "https://auth.example.org/fedcm/config.json" {
		t.Fatalf("provider_urls = %v", urls)
	}
}

func TestConfigHasEveryRequiredField(t *testing.T) {
	h := newTestHandler(t, &fakeStore{}, &fakeUsers{})
	w := httptest.NewRecorder()
	h.Config(w, httptest.NewRequest("GET", "/fedcm/config.json", nil))

	doc := decode(t, w)
	// accounts_endpoint, id_assertion_endpoint and login_url are REQUIRED — the
	// browser rejects a config missing any of them, with no useful diagnostic.
	for _, k := range []string{"accounts_endpoint", "id_assertion_endpoint", "login_url"} {
		if doc[k] == nil || doc[k] == "" {
			t.Fatalf("config is missing required field %q", k)
		}
	}
	for _, k := range []string{"accounts_endpoint", "id_assertion_endpoint", "client_metadata_endpoint", "disconnect_endpoint"} {
		v, _ := doc[k].(string)
		// Relative on purpose: they resolve against the config URL, so they are
		// same-origin with it by construction rather than by a hard-coded host.
		if !strings.HasPrefix(v, "/fedcm/") {
			t.Fatalf("%s = %q, want a relative /fedcm/ path", k, v)
		}
	}
	// login_url must be on the IdP origin — it is the only place the browser's
	// login-status bit can be set.
	if lu, _ := doc["login_url"].(string); !strings.HasPrefix(lu, "https://auth.example.org/") {
		t.Fatalf("login_url = %q, want it on the IdP origin", lu)
	}
	branding, _ := doc["branding"].(map[string]any)
	icons, _ := branding["icons"].([]any)
	if len(icons) == 0 {
		t.Fatal("branding.icons must not be empty")
	}
}

// ── Accounts ──────────────────────────────────────────────────────────────────────────────────────────

func TestAccountsReturnsTheSignedInAccount(t *testing.T) {
	u := testUser(t)
	store := &fakeStore{consents: map[string][]string{"rp-demo": {oidc.ScopeOpenID}}}
	h := newTestHandler(t, store, &fakeUsers{user: u})

	w := httptest.NewRecorder()
	h.Accounts(w, withSession(httptest.NewRequest("GET", "/fedcm/accounts", nil), u))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	accounts, _ := decode(t, w)["accounts"].([]any)
	if len(accounts) != 1 {
		t.Fatalf("accounts = %v, want exactly one", accounts)
	}
	a, _ := accounts[0].(map[string]any)
	if a["id"] != u.ID.String() {
		t.Fatalf("id = %v, want %s", a["id"], u.ID)
	}
	if a["email"] != "ada@example.org" || a["name"] != "Ada Lovelace" {
		t.Fatalf("account = %v", a)
	}
	// approved_clients is what suppresses the browser's disclosure prompt, so it has
	// to come from real consent rows — never be assumed.
	approved, _ := a["approved_clients"].([]any)
	if len(approved) != 1 || approved[0] != "rp-demo" {
		t.Fatalf("approved_clients = %v", approved)
	}
}

func TestAccountsRejectsWithoutASession(t *testing.T) {
	h := newTestHandler(t, &fakeStore{}, &fakeUsers{})
	w := httptest.NewRecorder()
	h.Accounts(w, httptest.NewRequest("GET", "/fedcm/accounts", nil))
	// 401 specifically: it is how the browser tells "signed out" (offer login_url)
	// apart from "signed in with no accounts".
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAccountsRejectsADeactivatedUser(t *testing.T) {
	u := testUser(t)
	u.Status = types.UserStatusSuspended
	h := newTestHandler(t, &fakeStore{}, &fakeUsers{user: u})
	w := httptest.NewRecorder()
	h.Accounts(w, withSession(httptest.NewRequest("GET", "/fedcm/accounts", nil), u))
	// The token may still be within its lifetime; the account is what matters here.
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a suspended account", w.Code)
	}
}

func TestAccountsReportsNoApprovalsWhenTheLookupFails(t *testing.T) {
	u := testUser(t)
	store := &fakeStore{listErr: sql.ErrConnDone}
	h := newTestHandler(t, store, &fakeUsers{user: u})
	w := httptest.NewRecorder()
	h.Accounts(w, withSession(httptest.NewRequest("GET", "/fedcm/accounts", nil), u))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a consent-lookup failure must not block sign-in", w.Code)
	}
	accounts, _ := decode(t, w)["accounts"].([]any)
	a, _ := accounts[0].(map[string]any)
	approved, _ := a["approved_clients"].([]any)
	if len(approved) != 0 {
		// Claiming approval we could not verify would silently skip the disclosure.
		t.Fatalf("approved_clients = %v, want empty on lookup failure", approved)
	}
}

// ── Assertion ─────────────────────────────────────────────────────────────────────────────────────────

func assertionRequest(form url.Values, origin string) *http.Request {
	r := httptest.NewRequest("POST", "/fedcm/assertion", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Dest", middleware.WebIdentityDest)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestAssertionMintsAVerifiableIDToken(t *testing.T) {
	u := testUser(t)
	store := &fakeStore{client: testClient(), consents: map[string][]string{}}
	h := newTestHandler(t, store, &fakeUsers{user: u})

	form := url.Values{
		"client_id":             {"rp-demo"},
		"account_id":            {u.ID.String()},
		"disclosure_text_shown": {"true"},
		"params":                {url.QueryEscape(`{"nonce":"n-abc123"}`)},
	}
	w := httptest.NewRecorder()
	h.Assertion(w, withSession(assertionRequest(form, "https://rp.example"), u))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	// CORS is mandatory even though no preflight fires: the token crosses into the
	// relying party's JS, so the browser enforces on the response alone.
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://rp.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want the exact RP origin", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want true", got)
	}

	token, _ := decode(t, w)["token"].(string)
	if token == "" {
		t.Fatal("no token in the response")
	}
	// Verified with the SAME KeyManager the OIDC flow uses — the whole point of
	// reusing it rather than introducing FedCM-specific crypto.
	claims, err := h.keys.VerifyIDToken(token, "https://auth.example.org", "rp-demo")
	if err != nil {
		t.Fatalf("the minted token does not verify: %v", err)
	}
	if claims.Subject != u.ID.String() {
		t.Fatalf("sub = %q, want %s", claims.Subject, u.ID)
	}
	if claims.Nonce != "n-abc123" {
		t.Fatalf("nonce = %q — the RP's replay defence was dropped", claims.Nonce)
	}
	if claims.Email != "ada@example.org" {
		t.Fatalf("email = %q, want it present under the default fields", claims.Email)
	}
	// disclosure_text_shown=true means the person was asked and agreed, so the grant
	// is recorded — that is what suppresses the prompt next time.
	if _, ok := store.saved["rp-demo"]; !ok {
		t.Fatal("consent was not recorded after the disclosure was shown")
	}
}

func TestAssertionAcceptsTheLegacyFlatNonce(t *testing.T) {
	// Chrome ≤142 sent the nonce as its own form field; 143 moved it into `params`.
	// Reading only one form would silently drop the nonce during the transition —
	// no error anywhere, just a token with no replay binding.
	u := testUser(t)
	h := newTestHandler(t, &fakeStore{client: testClient()}, &fakeUsers{user: u})
	form := url.Values{
		"client_id":  {"rp-demo"},
		"account_id": {u.ID.String()},
		"nonce":      {"n-legacy"},
	}
	w := httptest.NewRecorder()
	h.Assertion(w, withSession(assertionRequest(form, "https://rp.example"), u))

	token, _ := decode(t, w)["token"].(string)
	claims, err := h.keys.VerifyIDToken(token, "https://auth.example.org", "rp-demo")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Nonce != "n-legacy" {
		t.Fatalf("nonce = %q, want the flat form to still be honoured", claims.Nonce)
	}
}

func TestAssertionRejectsAnUnregisteredOrigin(t *testing.T) {
	u := testUser(t)
	h := newTestHandler(t, &fakeStore{client: testClient()}, &fakeUsers{user: u})
	form := url.Values{"client_id": {"rp-demo"}, "account_id": {u.ID.String()}}
	w := httptest.NewRecorder()
	h.Assertion(w, withSession(assertionRequest(form, "https://evil.example"), u))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — any site could otherwise mint tokens with a borrowed client_id", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("an unregistered origin must never be echoed back in ACAO")
	}
}

func TestAssertionRejectsAMissingOrigin(t *testing.T) {
	u := testUser(t)
	h := newTestHandler(t, &fakeStore{client: testClient()}, &fakeUsers{user: u})
	form := url.Values{"client_id": {"rp-demo"}, "account_id": {u.ID.String()}}
	w := httptest.NewRecorder()
	h.Assertion(w, withSession(assertionRequest(form, ""), u))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a request with no Origin", w.Code)
	}
}

func TestAssertionRejectsAnUnknownClient(t *testing.T) {
	u := testUser(t)
	h := newTestHandler(t, &fakeStore{}, &fakeUsers{user: u})
	form := url.Values{"client_id": {"nobody"}, "account_id": {u.ID.String()}}
	w := httptest.NewRecorder()
	h.Assertion(w, withSession(assertionRequest(form, "https://rp.example"), u))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestAssertionRejectsAnAccountThatIsNotTheSession(t *testing.T) {
	u := testUser(t)
	other := types.NewID()
	h := newTestHandler(t, &fakeStore{client: testClient()}, &fakeUsers{user: u})
	form := url.Values{"client_id": {"rp-demo"}, "account_id": {other.String()}}
	w := httptest.NewRecorder()
	h.Assertion(w, withSession(assertionRequest(form, "https://rp.example"), u))

	// Deliberately NOT "substitute the session's account and carry on" — that would
	// make the account_id in the request decorative.
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 on an account mismatch", w.Code)
	}
}

func TestAssertionReportsSignedOutWithCORSAttached(t *testing.T) {
	h := newTestHandler(t, &fakeStore{client: testClient()}, &fakeUsers{})
	form := url.Values{"client_id": {"rp-demo"}, "account_id": {types.NewID().String()}}
	w := httptest.NewRecorder()
	h.Assertion(w, assertionRequest(form, "https://rp.example"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	// Without CORS on the error the browser blocks the response and the relying
	// party sees an opaque network failure instead of "you are signed out".
	if w.Header().Get("Access-Control-Allow-Origin") != "https://rp.example" {
		t.Fatal("the signed-out error must still carry CORS headers")
	}
	errObj, _ := decode(t, w)["error"].(map[string]any)
	if errObj["code"] != "access_denied" {
		t.Fatalf("error.code = %v, want the FedCM/OAuth2 shape", errObj["code"])
	}
}

func TestAssertionWithoutDisclosureRecordsNoConsent(t *testing.T) {
	u := testUser(t)
	store := &fakeStore{client: testClient()}
	h := newTestHandler(t, store, &fakeUsers{user: u})
	form := url.Values{
		"client_id":             {"rp-demo"},
		"account_id":            {u.ID.String()},
		"disclosure_text_shown": {"false"},
	}
	w := httptest.NewRecorder()
	h.Assertion(w, withSession(assertionRequest(form, "https://rp.example"), u))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(store.saved) != 0 {
		t.Fatal("consent must only be recorded when the person was actually shown the disclosure")
	}
}

// ── Client metadata + disconnect ──────────────────────────────────────────────────────────────────────

func TestClientMetadataNeedsAClientID(t *testing.T) {
	h := newTestHandler(t, &fakeStore{client: testClient()}, &fakeUsers{})
	w := httptest.NewRecorder()
	h.ClientMetadata(w, httptest.NewRequest("GET", "/fedcm/client-metadata", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestClientMetadataDerivesLinksFromTheRegisteredOrigin(t *testing.T) {
	c := testClient()
	c.LogoURL = sql.NullString{String: "https://rp.example/logo.png", Valid: true}
	h := newTestHandler(t, &fakeStore{client: c}, &fakeUsers{})
	w := httptest.NewRecorder()
	h.ClientMetadata(w, httptest.NewRequest("GET", "/fedcm/client-metadata?client_id=rp-demo", nil))

	doc := decode(t, w)
	if doc["privacy_policy_url"] != "https://rp.example/privacy" {
		t.Fatalf("privacy_policy_url = %v", doc["privacy_policy_url"])
	}
	if doc["terms_of_service_url"] != "https://rp.example/terms" {
		t.Fatalf("terms_of_service_url = %v", doc["terms_of_service_url"])
	}
}

func TestDisconnectDropsTheConsentRow(t *testing.T) {
	u := testUser(t)
	store := &fakeStore{client: testClient(), consents: map[string][]string{"rp-demo": {oidc.ScopeOpenID}}}
	h := newTestHandler(t, store, &fakeUsers{user: u})

	form := url.Values{"client_id": {"rp-demo"}, "account_hint": {u.ID.String()}}
	r := httptest.NewRequest("POST", "/fedcm/disconnect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://rp.example")
	w := httptest.NewRecorder()
	h.Disconnect(w, withSession(r, u))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("disconnect needs credentialed CORS too")
	}
	if len(store.deleted) != 1 || store.deleted[0] != "rp-demo" {
		t.Fatalf("deleted = %v", store.deleted)
	}
	if decode(t, w)["account_id"] != u.ID.String() {
		t.Fatalf("account_id = %v", decode(t, w)["account_id"])
	}
}

func TestDisconnectRejectsAnUnregisteredOrigin(t *testing.T) {
	u := testUser(t)
	h := newTestHandler(t, &fakeStore{client: testClient()}, &fakeUsers{user: u})
	form := url.Values{"client_id": {"rp-demo"}}
	r := httptest.NewRequest("POST", "/fedcm/disconnect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.Disconnect(w, withSession(r, u))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// ── Login page ────────────────────────────────────────────────────────────────────────────────────────

func TestLoginPageRedirectsAnAnonymousVisitor(t *testing.T) {
	h := newTestHandler(t, &fakeStore{}, &fakeUsers{})
	w := httptest.NewRecorder()
	h.LoginPage(w, httptest.NewRequest("GET", "/fedcm/login", nil))

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want a 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://www.example.org/login?next=") {
		t.Fatalf("Location = %q", loc)
	}
	// It must come back here, or the login-status bit is never set and FedCM keeps
	// believing the person is signed out.
	if !strings.Contains(loc, url.QueryEscape("https://auth.example.org/fedcm/login")) {
		t.Fatalf("Location = %q, want a next= that returns to the FedCM login page", loc)
	}
}

func TestLoginPageReportsLoggedInStatus(t *testing.T) {
	u := testUser(t)
	h := newTestHandler(t, &fakeStore{}, &fakeUsers{user: u})
	w := httptest.NewRecorder()
	h.LoginPage(w, withSession(httptest.NewRequest("GET", "/fedcm/login", nil), u))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got := w.Header().Get(middleware.SetLoginHeader); got != "logged-in" {
		t.Fatalf("%s = %q, want logged-in", middleware.SetLoginHeader, got)
	}
	body := w.Body.String()
	if !strings.Contains(body, "navigator.login") {
		t.Fatal("the page must also set the status via the JS API")
	}
	// The server-wide CSP is `default-src 'none'`, which would block that script.
	// A nonce grants exactly this one script rather than opening 'unsafe-inline'.
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "nonce-") {
		t.Fatalf("CSP = %q, want a script nonce", csp)
	}
	if strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatal("script-src must not fall back to unsafe-inline")
	}
}

// ── Pure helpers ──────────────────────────────────────────────────────────────────────────────────────

func TestFedCMScopesMapping(t *testing.T) {
	cases := []struct {
		fields string
		want   []string
	}{
		// Absent fields = the browser's default disclosure (name, email, picture).
		// Mapping it to "everything" would hand out more than the person was shown.
		{"", []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}},
		{"name,email,picture", []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}},
		{"email", []string{oidc.ScopeOpenID, oidc.ScopeEmail}},
		{"name", []string{oidc.ScopeOpenID, oidc.ScopeProfile}},
		{"unknown-field", []string{oidc.ScopeOpenID}},
	}
	for _, c := range cases {
		got := fedCMScopes(c.fields)
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Fatalf("fedCMScopes(%q) = %v, want %v", c.fields, got, c.want)
		}
	}
}

func TestFedCMNoncePrefersParams(t *testing.T) {
	if got := fedCMNonce(url.QueryEscape(`{"nonce":"from-params"}`), "flat"); got != "from-params" {
		t.Fatalf("got %q, want the params form to win", got)
	}
	if got := fedCMNonce("", "flat"); got != "flat" {
		t.Fatalf("got %q, want the flat fallback", got)
	}
	// An unparseable params blob must fall back, not panic and not return garbage.
	if got := fedCMNonce("not-json", "flat"); got != "flat" {
		t.Fatalf("got %q, want the flat fallback on unparseable params", got)
	}
	// Chrome sends params already percent-encoded; a server that decoded twice, or
	// not at all, would read no nonce and bind nothing.
	if got := fedCMNonce(`{"nonce":"raw-json"}`, ""); got != "raw-json" {
		t.Fatalf("got %q, want an un-encoded params blob to parse too", got)
	}
}
