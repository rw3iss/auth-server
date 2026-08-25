package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/auth/oidc"
	"github.com/rw3iss/auth/internal/domain"
	"github.com/rw3iss/auth/pkg/shared/errors"
	"github.com/rw3iss/auth/pkg/shared/types"
)

// FedCMHandler implements the Federated Credential Management provider surface —
// "Sign in with CivicGate", brokered by the BROWSER instead of by third-party
// cookies or a popup.
//
// THE FLOW, end to end:
//
//	relying party                    browser                    auth.civicgate.org
//	navigator.credentials.get() ───────►│                                 │
//	                                    │ GET civicgate.org/.well-known/web-identity
//	                                    │ GET /fedcm/config.json ────────►│
//	                                    │ GET /fedcm/accounts (cookie) ──►│
//	                                    │ ◄──── the signed-in accounts    │
//	                            [browser draws the account chooser]       │
//	                                    │ POST /fedcm/assertion ─────────►│
//	◄──── IdentityCredential.token ─────│ ◄──── {"token": "<id_token>"}   │
//
// WHY THIS IS DIFFERENT FROM THE OIDC HANDLER NEXT DOOR. In OIDC we own the
// interaction: our page, our consent screen, our redirect. Here the BROWSER owns
// it. It calls these endpoints itself, so:
//
//   - There is no Authorization header to read. The only credential the browser
//     can present is a cookie, which is why the session cookie must be
//     SameSite=None (middleware.CookieOptions.CrossSite) for any of this to work.
//   - The accounts endpoint is never told WHICH relying party is asking. That is
//     the privacy property FedCM exists to provide — the IdP cannot build a log of
//     "this person visited that site" simply by being asked about them.
//   - Access control is `Sec-Fetch-Dest: webidentity`, a forbidden header name no
//     page script can set. See middleware.RequireWebIdentity.
//
// EVERYTHING CRYPTOGRAPHIC IS REUSED. The token minted here is an ordinary OIDC
// ID token from the same KeyManager, verifiable against the same JWKS, and the
// relying party is the same registered oauth_clients row. FedCM is a new way to
// ASK for identity, not a second identity system.
type FedCMHandler struct {
	keys     *oidc.KeyManager
	store    FedCMStore
	users    FedCMUsers
	issuer   string
	loginURL string
	branding FedCMBranding
}

// FedCMStore is the relying-party + consent persistence FedCM needs. Narrowed to
// an interface so the handler is testable without a database — *oidc.Store is the
// only production implementation, and deliberately so: a second client registry
// would eventually disagree with the first about who is allowed to ask.
type FedCMStore interface {
	GetClient(ctx context.Context, clientID string) (*oidc.Client, error)
	GetConsent(ctx context.Context, userID, clientID string) ([]string, error)
	SaveConsent(ctx context.Context, userID, clientID string, scopes []string) error
	ListConsentedClients(ctx context.Context, userID string) ([]string, error)
	DeleteConsent(ctx context.Context, userID, clientID string) error
}

// FedCMUsers is the account lookup. *auth.AuthService implements it.
type FedCMUsers interface {
	GetUserByID(ctx context.Context, userID types.ID) (*domain.User, error)
}

// FedCMBranding is what the browser paints in its own account-chooser dialog. The
// browser renders this chrome, not us, so these are the only visual controls an
// IdP has in the FedCM flow.
type FedCMBranding struct {
	Name            string
	IconURL         string
	IconSize        int
	BackgroundColor string
	Color           string
}

// DefaultFedCMBranding is CivicGate's chooser styling — the dark product theme, so
// the browser dialog does not read as a different product than the site behind it.
func DefaultFedCMBranding() FedCMBranding {
	return FedCMBranding{
		Name: "CivicGate",
		// 192px clears both Chrome minimums (25px passive, 40px active/button mode).
		IconURL:         "https://www.civicgate.org/icon-192.png",
		IconSize:        192,
		BackgroundColor: "#0f1115",
		Color:           "#e6e6ea",
	}
}

// NewFedCMHandler builds the handler. loginURL is where an anonymous visitor to
// the FedCM login page is sent to authenticate — normally the product's own login
// UI, which is on a different origin than this server.
func NewFedCMHandler(keys *oidc.KeyManager, store FedCMStore, users FedCMUsers, issuer, loginURL string, branding FedCMBranding) *FedCMHandler {
	return &FedCMHandler{keys: keys, store: store, users: users, issuer: issuer, loginURL: loginURL, branding: branding}
}

// ── Discovery ─────────────────────────────────────────────────────────────────────────────────────────

// WellKnown serves /.well-known/web-identity.
//
// ⚠ DEPLOYMENT NOTE, and it is the single easiest thing to get wrong: the browser
// fetches this file from the REGISTRABLE DOMAIN (eTLD+1) of the config URL, not
// from the config URL's own origin. With a config at
// https://auth.civicgate.org/fedcm/config.json the browser requests
//
//	https://civicgate.org/.well-known/web-identity
//
// which this server does not serve — that host is the web app's vhost. The route
// is registered here anyway because it is correct for any deployment where the IdP
// IS the registrable domain (localhost in development, a single-host install in
// production), and because a wrong-but-present file is easier to diagnose than a
// missing one. Redirects do NOT help: the browser fetches the well-known with
// redirect mode "error".
//
// The check is also SKIPPED entirely when the relying party is same-site with the
// IdP, so CivicGate's own pages federate against it without this file existing.
// It matters for genuinely third-party relying parties, which is the point.
func (h *FedCMHandler) WellKnown(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"provider_urls": []string{h.issuer + "/fedcm/config.json"},
	})
}

// Config serves /fedcm/config.json — the document the relying party names in
// `navigator.credentials.get({ identity: { providers: [{ configURL }] } })`.
//
// Endpoint URLs are emitted RELATIVE. They resolve against this document's URL, so
// they are same-origin with it by construction — which the spec requires and which
// a hard-coded absolute URL would quietly break the first time the issuer moved.
func (h *FedCMHandler) Config(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"accounts_endpoint":        "/fedcm/accounts",
		"id_assertion_endpoint":    "/fedcm/assertion",
		"client_metadata_endpoint": "/fedcm/client-metadata",
		"disconnect_endpoint":      "/fedcm/disconnect",
		// REQUIRED. The browser opens this when its login-status bit for this origin
		// is logged-out or unknown. It must be on the IdP origin: it is the only place
		// that can set the login status (Set-Login / navigator.login.setStatus) and
		// close the dialog.
		"login_url": h.issuer + "/fedcm/login",
		"branding": map[string]any{
			"name":             h.branding.Name,
			"background_color": h.branding.BackgroundColor,
			"color":            h.branding.Color,
			"icons": []map[string]any{
				{"url": h.branding.IconURL, "size": h.branding.IconSize},
			},
		},
	}
	// Short cache: long enough to save a round trip on repeat sign-ins, short enough
	// that changing an endpoint path is not a flag day for every relying party.
	w.Header().Set("Cache-Control", "public, max-age=600")
	writeJSON(w, http.StatusOK, doc)
}

// ── Accounts ──────────────────────────────────────────────────────────────────────────────────────────

// fedCMAccount is one row of the browser's account chooser.
type fedCMAccount struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	Username  string `json:"username,omitempty"`
	GivenName string `json:"given_name,omitempty"`
	Picture   string `json:"picture,omitempty"`
	// ApprovedClients is what decides whether the browser shows the "you are about
	// to share your name and email with X" disclosure. Reporting a client here that
	// the person never actually approved would silently skip that disclosure, so it
	// is read from the SAME oauth_consents table the OIDC consent screen writes.
	ApprovedClients []string `json:"approved_clients"`
	LoginHints      []string `json:"login_hints,omitempty"`
}

// Accounts serves GET /fedcm/accounts — cookie-authenticated, and the one endpoint
// that is never told which relying party is asking.
//
// The route wraps this in AuthenticateCookie, which answers 401 when there is no
// session. 401 is the correct FedCM answer for "signed out": it is how the browser
// tells that apart from "signed in with zero accounts", and it is what makes it
// offer the login_url instead of failing the whole request.
func (h *FedCMHandler) Accounts(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeError(w, errors.Unauthorized("No active session"))
		return
	}

	// Re-read the user rather than trusting the token's copy of their profile. An
	// access token can outlive a deactivation, and this endpoint is the one that
	// decides whether a person still exists as far as every relying party is
	// concerned.
	user, err := h.users.GetUserByID(r.Context(), claims.UserID)
	if err != nil || user == nil || !user.IsActive() {
		writeError(w, errors.Unauthorized("No active session"))
		return
	}

	approved, err := h.store.ListConsentedClients(r.Context(), user.ID.String())
	if err != nil {
		// Degrade to "nothing approved". The cost is one extra disclosure prompt; the
		// alternative — failing the sign-in outright — is worse, and claiming approval
		// we could not verify would be worse still.
		approved = []string{}
	}
	if approved == nil {
		approved = []string{}
	}

	acct := fedCMAccount{
		ID:              user.ID.String(),
		Name:            strings.TrimSpace(user.FirstName + " " + user.LastName),
		Email:           string(user.Email),
		GivenName:       user.FirstName,
		Picture:         user.AvatarURL,
		ApprovedClients: approved,
		LoginHints:      []string{string(user.Email)},
	}
	if user.DisplayName != "" {
		acct.Username = user.DisplayName
	}
	// An account with none of name/email/username/tel is rejected by the browser as
	// unrenderable. A person with no name set still has an email, but be explicit
	// rather than shipping a row the chooser silently drops.
	if acct.Name == "" && acct.Email == "" && acct.Username == "" {
		writeJSON(w, http.StatusOK, map[string]any{"accounts": []fedCMAccount{}})
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"accounts": []fedCMAccount{acct}})
}

// ── ID assertion ──────────────────────────────────────────────────────────────────────────────────────

// Assertion serves POST /fedcm/assertion — the endpoint that actually mints the
// token, and the only one where a mistake hands someone else's identity away.
//
// FOUR THINGS ARE VALIDATED, and each one is load-bearing:
//
//  1. Sec-Fetch-Dest: webidentity (route middleware) — the browser made this call.
//  2. client_id names a REGISTERED, active relying party.
//  3. The Origin header is an origin that client registered. Without this, any
//     site could pass someone else's client_id and receive tokens minted for them.
//  4. account_id matches the session's own user. The browser sends the account the
//     person picked; a mismatch means the request was tampered with, so we mint for
//     the SESSION, never for the id we were handed.
func (h *FedCMHandler) Assertion(w http.ResponseWriter, r *http.Request) {
	// ORDER MATTERS HERE. The client and origin are validated FIRST so the CORS
	// headers are on the response before any session check can fail. Without them a
	// 401 is blocked by the browser and reaches the relying party as an opaque
	// network error — "something went wrong" instead of "you are signed out", which
	// is the difference between a fixable bug and an unfixable one.
	if err := r.ParseForm(); err != nil {
		writeFedCMError(w, http.StatusBadRequest, "invalid_request", "Could not parse the request body")
		return
	}

	clientID := r.FormValue("client_id")
	accountID := r.FormValue("account_id")
	origin := r.Header.Get("Origin")
	if clientID == "" || accountID == "" {
		writeFedCMError(w, http.StatusBadRequest, "invalid_request", "client_id and account_id are required")
		return
	}

	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeFedCMError(w, http.StatusUnauthorized, "unauthorized_client", "Unknown or inactive client")
		return
	}
	// The Origin header is set by the browser and cannot be forged by page script,
	// so matching it against the client's registered origins is what binds a token
	// to the site that is genuinely allowed to receive it. Exact match, no
	// wildcards — the same rule, and the same reason, as the redirect_uri allow-list.
	if origin == "" || !client.AllowsOrigin(origin) {
		writeFedCMError(w, http.StatusForbidden, "unauthorized_client", "This origin is not registered for the client")
		return
	}

	// CORS must be on the response even though no preflight fires: the body crosses
	// into the relying party's JavaScript, so the browser enforces the check on the
	// response alone. The exact origin, never "*" — "*" is invalid with credentials
	// and the browser would drop the response.
	setFedCMCORS(w, origin)

	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		writeFedCMError(w, http.StatusUnauthorized, "access_denied", "No active session")
		return
	}
	if accountID != claims.UserID.String() {
		// Do not silently substitute the session's account. A mismatch is either a
		// tampered request or a stale chooser, and issuing a token anyway would mean
		// the id in the request never mattered.
		writeFedCMError(w, http.StatusForbidden, "access_denied", "The selected account does not match this session")
		return
	}

	user, err := h.users.GetUserByID(r.Context(), claims.UserID)
	if err != nil || user == nil || !user.IsActive() {
		writeFedCMError(w, http.StatusUnauthorized, "access_denied", "No active session")
		return
	}

	// What the relying party may receive. `fields` is the browser telling us which
	// of name/email/username/picture/tel it asked the person to disclose; it is
	// intersected with what the client is registered for, so a client cannot widen
	// its own reach by asking the browser for more.
	scopes := client.FilterScopes(fedCMScopes(r.FormValue("fields")))

	// Nonce. Chrome 143 moved it INSIDE the percent-encoded `params` JSON blob and
	// Chrome 145 drops the flat form; read both so the server works either side of
	// that change rather than silently issuing un-bound tokens during it.
	nonce := fedCMNonce(r.FormValue("params"), r.FormValue("nonce"))

	idToken, err := h.keys.NewIDToken(oidc.IDTokenInput{
		Issuer:     h.issuer,
		Subject:    user.ID.String(),
		Audience:   clientID,
		Nonce:      nonce,
		AuthTime:   time.Now(),
		Scopes:     scopes,
		Email:      string(user.Email),
		EmailVerif: user.EmailVerified,
		Name:       strings.TrimSpace(user.FirstName + " " + user.LastName),
		GivenName:  user.FirstName,
		FamilyName: user.LastName,
		Username:   user.DisplayName,
		Picture:    user.AvatarURL,
		AppCode:    nullString(client.AppCode.String, client.AppCode.Valid),
	})
	if err != nil {
		writeFedCMError(w, http.StatusInternalServerError, "server_error", "Could not issue a token")
		return
	}

	// Record the grant when the browser says it showed the disclosure and the person
	// went ahead. This is what populates approved_clients on the next sign-in, so
	// they are not asked the same question forever — and it is written to the SAME
	// table as the OIDC consent screen, so revoking in one place revokes in both.
	if r.FormValue("disclosure_text_shown") == "true" {
		granted, _ := h.store.GetConsent(r.Context(), user.ID.String(), clientID)
		_ = h.store.SaveConsent(r.Context(), user.ID.String(), clientID, unionScopes(granted, scopes))
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"token": idToken})
}

// ── Client metadata ───────────────────────────────────────────────────────────────────────────────────

// ClientMetadata serves GET /fedcm/client-metadata?client_id=… — the relying
// party's privacy policy and terms links, which the browser shows inside its own
// disclosure UI.
//
// UNCREDENTIALED: the browser sends no cookies here, so this must never consult a
// session or return anything about a person. It answers a question about the
// CLIENT.
func (h *FedCMHandler) ClientMetadata(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		writeFedCMError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeFedCMError(w, http.StatusNotFound, "invalid_request", "Unknown or inactive client")
		return
	}

	out := map[string]any{}
	// We hold no policy URLs per client today, so derive them from the client's own
	// origin rather than inventing or omitting. An omitted key renders as no link,
	// which is honest; a fabricated one would send a person to a 404 while claiming
	// it was that company's privacy policy.
	if base := client.PrimaryOrigin(); base != "" {
		out["privacy_policy_url"] = base + "/privacy"
		out["terms_of_service_url"] = base + "/terms"
	}
	if client.LogoURL.Valid && client.LogoURL.String != "" {
		out["icons"] = []map[string]any{{"url": client.LogoURL.String}}
	}
	w.Header().Set("Cache-Control", "public, max-age=600")
	writeJSON(w, http.StatusOK, out)
}

// ── Disconnect ────────────────────────────────────────────────────────────────────────────────────────

// Disconnect serves POST /fedcm/disconnect — the relying party asking us to forget
// that this person ever connected to it.
//
// It drops the consent row, so the next sign-in shows the disclosure again. It does
// NOT end the person's CivicGate session: disconnecting from one site must not sign
// them out of everything, and conflating the two would make "disconnect" a
// surprisingly destructive button.
func (h *FedCMHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if err := r.ParseForm(); err != nil {
		writeFedCMError(w, http.StatusBadRequest, "invalid_request", "Could not parse the request body")
		return
	}
	clientID := r.FormValue("client_id")
	origin := r.Header.Get("Origin")
	if clientID == "" {
		writeFedCMError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeFedCMError(w, http.StatusUnauthorized, "unauthorized_client", "Unknown or inactive client")
		return
	}
	if origin == "" || !client.AllowsOrigin(origin) {
		writeFedCMError(w, http.StatusForbidden, "unauthorized_client", "This origin is not registered for the client")
		return
	}
	setFedCMCORS(w, origin)

	if claims == nil {
		writeFedCMError(w, http.StatusUnauthorized, "access_denied", "No active session")
		return
	}
	if err := h.store.DeleteConsent(r.Context(), claims.UserID.String(), clientID); err != nil {
		writeFedCMError(w, http.StatusInternalServerError, "server_error", "Could not disconnect the account")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"account_id": claims.UserID.String()})
}

// ── Login page ────────────────────────────────────────────────────────────────────────────────────────

// LoginPage serves GET /fedcm/login — the `login_url` from the config document.
//
// WHY THIS PAGE HAS TO EXIST ON THIS ORIGIN. The browser keeps a login-status bit
// per IdP ORIGIN, and while it reads logged-out it will not call the accounts
// endpoint at all — FedCM fails with a valid session sitting right there. The bit
// can only be set from the IdP's own origin, and the product's login UI is on a
// different one, so a login POST from there cannot set it. This page closes that
// gap: it is same-origin, so `navigator.login.setStatus()` counts.
//
// Deliberately NOT behind RequireWebIdentity — the browser opens it as a top-level
// navigation, where Sec-Fetch-Dest is "document".
func (h *FedCMHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	if middleware.GetClaims(r.Context()) == nil {
		// Signed out: a plain 302 to the product's login UI, which returns here. A
		// server-side redirect rather than a scripted one — it needs no CSP exception,
		// works with JavaScript disabled, and leaves nothing to go wrong in between.
		sep := "?"
		if strings.Contains(h.loginURL, "?") {
			sep = "&"
		}
		http.Redirect(w, r, h.loginURL+sep+"next="+url.QueryEscape(h.issuer+"/fedcm/login"), http.StatusFound)
		return
	}

	// Signed in. Report it both ways: the header, because this is a top-level
	// navigation to the IdP origin and that is where Set-Login counts, and the JS
	// API, because that is the path the spec documents for a login page finishing
	// without a further navigation.
	middleware.SetLoginStatus(w, true)

	nonce, err := randomToken(16)
	if err != nil {
		writeError(w, errors.Internal("Could not render the sign-in page"))
		return
	}
	// The server-wide CSP is `default-src 'none'`, which blocks inline script. Grant
	// exactly this one script a nonce rather than switching the page to
	// 'unsafe-inline', which would allow any injected script on the page too.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — CivicGate</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6ea;display:flex;
min-height:100vh;align-items:center;justify-content:center;margin:0}
main{max-width:22rem;padding:2rem;text-align:center}</style></head><body><main>
<p>You are signed in to CivicGate. Returning…</p>
<script nonce="` + nonce + `">
(function(){
  try { if (navigator.login && navigator.login.setStatus) navigator.login.setStatus("logged-in"); } catch (e) {}
  try { if (window.IdentityProvider && IdentityProvider.close) IdentityProvider.close(); } catch (e) {}
})();
</script>
</main></body></html>`))
}

// ── Helpers ───────────────────────────────────────────────────────────────────────────────────────────

// setFedCMCORS echoes the exact relying-party origin and allows credentials.
//
// Called only AFTER the origin has been matched against a registered client, so
// this never echoes an arbitrary caller. Echoing first and validating later is the
// classic way an allow-list turns into "allow anyone who asks".
func setFedCMCORS(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Vary", "Origin")
}

// writeFedCMError emits the shape the FedCM spec defines — `error.code` from the
// OAuth2 error list, plus an optional human-readable `url`.
//
// It carries the repo's `message` alongside, so an operator reading a log or a curl
// response gets the same detail every other endpoint here provides. The browser
// reads `code` and `url` and ignores the rest, so the two conventions coexist
// rather than one having to lose.
func writeFedCMError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

// fedCMScopes maps the browser's `fields` list onto this server's OIDC scopes, so
// scope-based claim filtering in NewIDToken is the single place that decides what a
// token carries — FedCM does not get its own parallel notion of "what may be shared".
//
// An absent `fields` means the browser used its default disclosure (name, email and
// picture), so that is what an absent value maps to. Mapping it to "everything"
// would hand out more than the person was shown.
func fedCMScopes(fields string) []string {
	if strings.TrimSpace(fields) == "" {
		return []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}
	}
	out := []string{oidc.ScopeOpenID}
	profile, email := false, false
	for _, f := range strings.Split(fields, ",") {
		switch strings.TrimSpace(f) {
		case "email":
			email = true
		case "name", "given_name", "username", "picture", "tel":
			profile = true
		}
	}
	if profile {
		out = append(out, oidc.ScopeProfile)
	}
	if email {
		out = append(out, oidc.ScopeEmail)
	}
	return out
}

// fedCMNonce extracts the relying party's nonce.
//
// TWO PLACES ON PURPOSE. Chrome ≤142 sent `nonce` as its own form field; Chrome 143
// moved it inside `params`, a percent-encoded JSON blob, and 145 removes the flat
// form. Reading `params` first and falling back keeps the token bound to the
// request across that transition instead of silently dropping the nonce — which
// would not error anywhere, it would just remove a replay defence.
func fedCMNonce(params, flat string) string {
	if params != "" {
		raw := params
		if decoded, err := url.QueryUnescape(params); err == nil {
			raw = decoded
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			if n, ok := parsed["nonce"].(string); ok && n != "" {
				return n
			}
		}
	}
	return flat
}

func unionScopes(a, b []string) []string { return union(a, b) }

func nullString(s string, valid bool) string {
	if !valid {
		return ""
	}
	return s
}
