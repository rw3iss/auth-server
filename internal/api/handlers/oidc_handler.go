package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/auth/oidc"
	auth "github.com/rw3iss/auth/internal/service/auth"
	"github.com/rw3iss/auth/pkg/shared/errors"
	jwtpkg "github.com/rw3iss/auth/internal/auth/jwt"
)

// OIDCHandler implements the OpenID Connect provider surface.
//
// THE FLOW, end to end:
//
//	 browser                     auth.civicgate.org                 relying party
//	   │  GET /oauth/authorize ────────►│                                  │
//	   │  (login if needed, consent)    │                                  │
//	   │  ◄──── 302 redirect_uri?code=… │                                  │
//	   │─────────────────────────────── code ────────────────────────────► │
//	   │                                │ ◄── POST /oauth/token (code+PKCE)│
//	   │                                │ ──── id_token + access_token ───►│
//	   │                                │ ◄── GET /userinfo (bearer)       │
//
// The relying party never sees the person's credentials, and verifies the id_token locally against JWKS.
type OIDCHandler struct {
	keys        *oidc.KeyManager
	store       *oidc.Store
	authService *auth.AuthService
	// Minting a SERVICE token needs the symmetric signer, not the OIDC KeyManager (which holds the RS256
	// key used for id_tokens). Same signer the m2m registry uses, so both registries emit one token shape.
	jwtService  *jwtpkg.Service
	issuer      string
	// Where to send an unauthenticated /oauth/authorize — the login UI, which returns here afterwards.
	loginURL string
}

func NewOIDCHandler(keys *oidc.KeyManager, store *oidc.Store, authService *auth.AuthService, jwtService *jwtpkg.Service, issuer, loginURL string) *OIDCHandler {
	return &OIDCHandler{keys: keys, store: store, authService: authService, jwtService: jwtService, issuer: issuer, loginURL: loginURL}
}

// ── Discovery ─────────────────────────────────────────────────────────────────────────────────────────

// Discovery serves /.well-known/openid-configuration (OIDC Discovery 1.0).
//
// This single document is what makes the difference between "integrators hand-configure six URLs and
// usually get one wrong" and "point any OIDC library at the issuer and it works".
func (h *OIDCHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.issuer + "/api/v1/oauth/authorize",
		"token_endpoint":                        h.issuer + "/api/v1/oauth/token",
		"userinfo_endpoint":                     h.issuer + "/api/v1/oauth/userinfo",
		"jwks_uri":                              h.issuer + "/.well-known/jwks.json",
		"end_session_endpoint":                  h.issuer + "/api/v1/oauth/logout",
		"revocation_endpoint":                   h.issuer + "/api/v1/oauth/revoke",
		"scopes_supported":                      oidc.SupportedScopes,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		// DERIVED from what the token endpoint actually implements, never hand-listed. This document is
		// how every standards-compliant library decides what to attempt, so a grant listed here and not
		// served sends clients down a path that can only fail — which is what happened with
		// refresh_token: advertised, and answered with unsupported_grant_type.
		"grant_types_supported":                 oidc.SupportedGrants,
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		// Advertising S256 ONLY (not "plain") tells clients the weak variant will be refused, which is
		// what stops a library silently choosing it.
		"code_challenge_methods_supported": []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "azp",
			"email", "email_verified", "name", "given_name", "family_name",
			"preferred_username", "picture", "updated_at",
			"cg_app_code", "cg_namespaces", "cg_roles",
		},
		"service_documentation": "https://docs.civicgate.org/plans/identity/",
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, doc)
}

// JWKS serves /.well-known/jwks.json — the PUBLIC keys, by design.
func (h *OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	// Cacheable, but not for long: a short TTL is what lets a key rotation propagate without a flag day.
	w.Header().Set("Cache-Control", "public, max-age=600")
	writeJSON(w, http.StatusOK, h.keys.JWKS())
}

// ── Authorization endpoint ────────────────────────────────────────────────────────────────────────────

// Authorize handles GET/POST /oauth/authorize (RFC 6749 §4.1 + PKCE).
//
// ERROR HANDLING IS SPLIT ON PURPOSE. Before the redirect_uri is validated, errors render locally —
// redirecting an unvalidated URI is precisely the open-redirect this endpoint must not be. AFTER
// validation, errors go back to the client as `?error=` per the RFC, because by then we know where they
// belong.
func (h *OIDCHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	state := q.Get("state")
	nonce := q.Get("nonce")
	scopeRaw := q.Get("scope")
	challenge := q.Get("code_challenge")
	challengeMethod := q.Get("code_challenge_method")

	if clientID == "" || redirectURI == "" {
		writeError(w, errors.InvalidInput("client_id", "client_id and redirect_uri are required"))
		return
	}

	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil {
		// Unknown client → render locally. We have no verified place to send them.
		writeError(w, errors.InvalidInput("client_id", "Unknown or inactive client"))
		return
	}
	if !client.AllowsRedirect(redirectURI) {
		// NEVER redirect here. An unregistered redirect_uri is the open-redirect / code-theft vector.
		writeError(w, errors.InvalidInput("redirect_uri", "redirect_uri is not registered for this client"))
		return
	}

	// From here on, errors are delivered to the (now trusted) redirect_uri.
	fail := func(code, desc string) {
		u, _ := url.Parse(redirectURI)
		v := u.Query()
		v.Set("error", code)
		v.Set("error_description", desc)
		if state != "" {
			v.Set("state", state)
		}
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}

	if responseType != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	// Enforced at the AUTHORIZE step as well as at the token step. Checking only at the token endpoint
	// would walk the user through a full consent screen before refusing — the client is knowably
	// ineligible before anyone is asked to approve anything.
	if !client.AllowsGrant(oidc.GrantAuthorizationCode) {
		fail("unauthorized_client", "this client is not permitted to use the authorization_code grant")
		return
	}

	scopes := client.FilterScopes(oidc.ParseScopes(scopeRaw))
	if !oidc.HasScope(scopes, oidc.ScopeOpenID) {
		fail("invalid_scope", "the openid scope is required")
		return
	}

	// PKCE. Required for public clients always, and for confidential clients unless explicitly exempted:
	// a stolen code is useless without the verifier, which never leaves the real client.
	if client.RequirePKCE || client.IsPublic() {
		if challenge == "" {
			fail("invalid_request", "code_challenge is required (PKCE)")
			return
		}
		if challengeMethod != "S256" {
			// "plain" offers no protection against an attacker who saw the challenge — refuse it outright
			// rather than accept a flow that only looks protected.
			fail("invalid_request", "code_challenge_method must be S256")
			return
		}
	}

	// Who is logged in? The bearer token is how the browser proves an existing session.
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		// Not authenticated → send them to the login UI, which returns here with the same query intact.
		back := h.issuer + "/api/v1/oauth/authorize?" + r.URL.RawQuery
		sep := "?"
		if strings.Contains(h.loginURL, "?") {
			sep = "&"
		}
		http.Redirect(w, r, h.loginURL+sep+"next="+url.QueryEscape(back), http.StatusFound)
		return
	}
	userID := claims.UserID.String()

	// Consent. A trusted first-party client skips it; everyone else must have granted every scope asked
	// for, and any SENSITIVE scope forces a fresh prompt even if previously granted.
	if !client.Trusted {
		granted, _ := h.store.GetConsent(r.Context(), userID, clientID)
		if missing := missingScopes(scopes, granted); len(missing) > 0 {
			if q.Get("consent") == "granted" {
				_ = h.store.SaveConsent(r.Context(), userID, clientID, union(granted, scopes))
			} else {
				h.renderConsent(w, client, scopes, r.URL.RawQuery)
				return
			}
		}
	}

	code, err := randomToken(32)
	if err != nil {
		fail("server_error", "could not issue a code")
		return
	}
	err = h.store.SaveAuthCode(r.Context(), code, oidc.AuthCode{
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		Nonce:               nullable(nonce),
		CodeChallenge:       nullable(challenge),
		CodeChallengeMethod: nullable(challengeMethod),
		AuthTime:            time.Now(),
		// Short by design (RFC 6749 recommends ≤10 min). The code is a bearer credential in a URL, which
		// is the most-logged place a secret can be.
		ExpiresAt: time.Now().Add(2 * time.Minute),
	})
	if err != nil {
		fail("server_error", "could not persist the code")
		return
	}

	u, _ := url.Parse(redirectURI)
	v := u.Query()
	v.Set("code", code)
	if state != "" {
		v.Set("state", state)
	}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// renderConsent shows what a client is asking for, in plain language.
func (h *OIDCHandler) renderConsent(w http.ResponseWriter, c *oidc.Client, scopes []string, rawQuery string) {
	descriptions := map[string]string{
		oidc.ScopeOpenID:     "Confirm who you are",
		oidc.ScopeProfile:    "Your name, username and picture",
		oidc.ScopeEmail:      "Your email address",
		oidc.ScopeOffline:    "Stay signed in when you are not using the site",
		oidc.ScopeCivicLoc:   "Your city, state and country (never your street address)",
		oidc.ScopeCivicInt:   "The civic topics you follow",
		oidc.ScopePositions:  "The positions you have declared on issues",
		oidc.ScopeCivicActiv: "Your civic activity — representatives you have contacted and what you urged",
	}
	var rows strings.Builder
	for _, s := range scopes {
		label := descriptions[s]
		if label == "" {
			label = s
		}
		warn := ""
		if oidc.SensitiveScopes[s] {
			warn = ` <em style="color:#e8b44a">— sensitive</em>`
		}
		rows.WriteString("<li>" + htmlEscape(label) + warn + "</li>")
	}
	page := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize ` + htmlEscape(c.Name) + ` — CivicGate</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6ea;display:flex;min-height:100vh;
align-items:center;justify-content:center;margin:0}main{max-width:26rem;padding:2rem;border:1px solid #2a2a33;
border-radius:12px}h1{font-size:1.15rem}ul{padding-left:1.1rem;line-height:1.7}
.b{display:inline-block;padding:.6rem 1.1rem;border-radius:8px;text-decoration:none;font-weight:600}
.y{background:#4da3ff;color:#0f1115}.n{color:#9aa0aa;margin-left:.6rem}
small{color:#9aa0aa;display:block;margin-top:1.2rem;line-height:1.5}</style></head><body><main>
<h1>` + htmlEscape(c.Name) + ` wants to use your CivicGate account</h1>
<p>It is asking to:</p><ul>` + rows.String() + `</ul>
<form method="GET" action="/api/v1/oauth/authorize">` + hiddenInputs(rawQuery) + `
<input type="hidden" name="consent" value="granted">
<button class="b y" type="submit">Allow</button>
<a class="b n" href="/">Cancel</a></form>
<small>You can revoke this at any time in your CivicGate account settings.
CivicGate never shares your street address or postal code.</small>
</main></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

// ── UserInfo ──────────────────────────────────────────────────────────────────────────────────────────

// UserInfo serves the OIDC standard profile endpoint (Core §5.3), bearer-authenticated.
func (h *OIDCHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, errors.Unauthorized("A valid access token is required"))
		return
	}
	out := map[string]any{
		"sub":            claims.UserID.String(),
		"email":          claims.Email,
		"email_verified": true,
		"name":           strings.TrimSpace(claims.FirstName + " " + claims.LastName),
		"given_name":     claims.FirstName,
		"family_name":    claims.LastName,
		"cg_roles":       claims.Roles,
	}
	if claims.DisplayName != "" {
		out["preferred_username"] = claims.DisplayName
	}
	if claims.AppCode != "" {
		out["cg_app_code"] = claims.AppCode
	}
	writeJSON(w, http.StatusOK, out)
}

// ── Helpers ───────────────────────────────────────────────────────────────────────────────────────────

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func nullable(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func missingScopes(want, have []string) []string {
	out := []string{}
	for _, w := range want {
		// A sensitive scope always re-prompts, even if previously granted: consent for political-belief
		// data should be a decision the person remembers making, not one inherited from months ago.
		if oidc.SensitiveScopes[w] {
			out = append(out, w)
			continue
		}
		found := false
		for _, h := range have {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			out = append(out, w)
		}
	}
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func hiddenInputs(rawQuery string) string {
	var sb strings.Builder
	vals, _ := url.ParseQuery(rawQuery)
	for k, vs := range vals {
		if k == "consent" {
			continue
		}
		for _, v := range vs {
			sb.WriteString(fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, htmlEscape(k), htmlEscape(v)))
		}
	}
	return sb.String()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// clientFromRequest reads and authenticates the client on a token request.
//
// Basic auth is the RFC-preferred form and the body form is the widely-used one; both are accepted, with
// Basic winning, exactly as the authorization_code path already did. Returns nil (having written the
// error) when the client is unknown or its secret is wrong.
func (h *OIDCHandler) clientFromRequest(w http.ResponseWriter, r *http.Request) *oidc.Client {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, clientSecret = u, p
	}
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return nil
	}
	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return nil
	}
	if !client.IsPublic() {
		if clientSecret == "" || !checkSecret(client.ClientSecretHash.String, clientSecret) {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
			return nil
		}
	}
	return client
}

// ── Token endpoint: the refresh_token grant (RFC 6749 §6) ────────────────────────────────────────────

// tokenByRefresh exchanges a refresh token for a fresh pair.
//
// This grant was ADVERTISED in the discovery document and not implemented: the endpoint forwarded every
// non-authorization_code grant to the m2m handler, which serves only client_credentials and answered
// `unsupported_grant_type`. A client that did everything right — requested offline_access, stored the
// refresh token, came back when the access token expired — hit a wall at the URL we told it to use.
//
// An unknown client id falls through to the m2m handler rather than erroring, so a non-OIDC caller still
// reaches the registry that knows it.
func (h *OIDCHandler) tokenByRefresh(w http.ResponseWriter, r *http.Request, fallback http.HandlerFunc) {
	refresh := r.FormValue("refresh_token")
	if refresh == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	if _, err := h.store.GetClient(r.Context(), r.FormValue("client_id")); err != nil {
		if _, _, ok := r.BasicAuth(); !ok {
			fallback(w, r)
			return
		}
	}
	client := h.clientFromRequest(w, r)
	if client == nil {
		return
	}
	if !client.AllowsGrant(oidc.GrantRefreshToken) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not permitted to use the refresh_token grant")
		return
	}

	// The refresh token carries its own subject and is validated by the JWT service; the client
	// authentication above proves WHO is presenting it. Rotation semantics are whatever RefreshTokens
	// does for a first-party session — one implementation, so an OIDC refresh and a session refresh
	// cannot drift apart in how they revoke.
	pair, err := h.authService.RefreshTokens(r.Context(), refresh, nil)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(pair.ExpiresIn),
	})
}

// ── Token endpoint: the client_credentials grant (RFC 6749 §4.4) ─────────────────────────────────────

// tokenByClientCredentials issues a SERVICE token to an OIDC client that is registered for it.
//
// Before this, client_credentials reached only the separate `m2m_clients` registry, so an application
// created through /admin/applications could not use the grant however its grant_types were set — and the
// discovery document advertised it regardless. Now the two registries share one endpoint and one rule:
// the grant works iff the client is registered for it. Self-service clients still cannot be, because
// self-service registration hardcodes its grant list and refuses this one.
//
// An id that is not an OIDC client falls through to the m2m handler, so the existing machine clients keep
// working with no change on their side.
func (h *OIDCHandler) tokenByClientCredentials(w http.ResponseWriter, r *http.Request, fallback http.HandlerFunc) {
	clientID := r.FormValue("client_id")
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		clientID = u
	}
	if _, err := h.store.GetClient(r.Context(), clientID); err != nil {
		fallback(w, r)
		return
	}
	client := h.clientFromRequest(w, r)
	if client == nil {
		return
	}
	// A PUBLIC client has no secret, so it cannot authenticate itself — and this grant is nothing but
	// client authentication. Allowing it would hand a service token to anyone holding a public client id.
	if client.IsPublic() {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client",
			"client_credentials requires a confidential client with a secret")
		return
	}
	if !client.AllowsGrant(oidc.GrantClientCredentials) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not registered for the client_credentials grant")
		return
	}

	scopes := client.FilterScopes(strings.Fields(r.FormValue("scope")))
	appCode := ""
	if client.AppCode.Valid {
		appCode = client.AppCode.String
	}
	_ = appCode // carried on the client row; the service token is scoped by client + scopes, not app_code
	tok, err := h.jwtService.ServiceToken(r.Context(), client.ClientID, client.Name, scopes)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue a token")
		return
	}
	// RFC 6749 §4.4.3: no refresh token for this grant — the client can simply ask again.
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   tok.ExpiresIn,
		"scope":        strings.Join(scopes, " "),
	})
}

// ── Token endpoint: the authorization_code grant ──────────────────────────────────────────────────────

// Token handles POST /oauth/token — the single token URL discovery advertises, for every grant this
// server implements.
//
// THREE GRANTS, and each was in a different state before this:
//
//	authorization_code  worked
//	refresh_token       ADVERTISED BUT ABSENT. Anything that was not authorization_code fell through to
//	                    the m2m handler, which answers `unsupported_grant_type` for it — so a client that
//	                    correctly asked for offline_access, received a refresh token, and then tried to
//	                    use it at the advertised endpoint got a flat refusal. That is RFC 6749 §6, and
//	                    every standards-compliant library attempts it.
//	client_credentials  served only the SEPARATE m2m_clients registry, so an application registered
//	                    through /admin/applications or self-service could never use it whatever its
//	                    grant_types said.
//
// Client grant_types are now ENFORCED here (`AllowsGrant`) before any grant runs, so the column means
// what it says. The m2m fallback is preserved for client ids that are not OIDC clients at all.
func (h *OIDCHandler) Token(w http.ResponseWriter, r *http.Request, fallback http.HandlerFunc) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not parse the request body")
		return
	}
	grant := r.FormValue("grant_type")
	if !oidc.IsSupportedGrant(grant) {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"supported grant types are: "+strings.Join(oidc.SupportedGrants, ", "))
		return
	}
	if grant == oidc.GrantRefreshToken {
		h.tokenByRefresh(w, r, fallback)
		return
	}
	if grant == oidc.GrantClientCredentials {
		h.tokenByClientCredentials(w, r, fallback)
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	verifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	// Basic auth is the RFC-preferred client authentication; accept both.
	if u, p, ok := r.BasicAuth(); ok {
		clientID, clientSecret = u, p
	}
	if code == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code and client_id are required")
		return
	}

	client, err := h.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if !client.AllowsGrant(oidc.GrantAuthorizationCode) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not permitted to use the authorization_code grant")
		return
	}
	// A confidential client must prove itself. A public client cannot, which is exactly why PKCE is
	// mandatory for it — the verifier takes the place of the secret.
	if !client.IsPublic() {
		if clientSecret == "" || !checkSecret(client.ClientSecretHash.String, clientSecret) {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
			return
		}
	}

	stored, err := h.store.ConsumeAuthCode(r.Context(), code)
	if err != nil {
		// Unknown, already-redeemed and expired all collapse to one answer. A replayed code means the code
		// was probably intercepted; telling the caller WHICH failure occurred helps only an attacker.
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is not valid")
		return
	}
	if stored.ClientID != clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the code was issued to another client")
		return
	}
	// The redirect_uri must match the one the code was issued against (RFC 6749 §4.1.3) — this is what
	// stops a code minted for one registered URI being redeemed against another.
	if redirectURI != "" && redirectURI != stored.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")
		return
	}
	if stored.CodeChallenge.Valid && stored.CodeChallenge.String != "" {
		if !oidc.VerifyPKCE(stored.CodeChallenge.String, stored.CodeChallengeMethod.String, verifier) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	} else if client.RequirePKCE || client.IsPublic() {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE is required for this client")
		return
	}

	userID, err := uuid.Parse(stored.UserID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "bad subject")
		return
	}
	appCode := ""
	if client.AppCode.Valid {
		appCode = client.AppCode.String
	}
	pair, user, err := h.authService.IssueTokensForUser(r.Context(), userID, appCode)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "could not issue tokens")
		return
	}

	idToken, err := h.keys.NewIDToken(oidc.IDTokenInput{
		Issuer:     h.issuer,
		Subject:    stored.UserID,
		Audience:   clientID,
		Nonce:      stored.Nonce.String,
		AuthTime:   stored.AuthTime,
		Scopes:     stored.Scopes,
		Email:      string(user.Email),
		EmailVerif: user.EmailVerified,
		Name:       strings.TrimSpace(user.FirstName + " " + user.LastName),
		GivenName:  user.FirstName,
		FamilyName: user.LastName,
		Username:   user.DisplayName,
		AppCode:    appCode,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue id_token")
		return
	}

	resp := map[string]any{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"id_token":      idToken,
		"token_type":    "Bearer",
		"expires_in":    pair.ExpiresIn,
		// Echo the GRANTED scopes, which may be narrower than what was requested. A client that assumes it
		// got what it asked for will misbehave the first time a scope is refused.
		"scope": strings.Join(stored.Scopes, " "),
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, resp)
}

// EndSession implements RP-initiated logout (OIDC RP-Initiated Logout 1.0).
func (h *OIDCHandler) EndSession(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("post_logout_redirect_uri")
	clientID := r.URL.Query().Get("client_id")
	if redirect != "" && clientID != "" {
		// Only redirect to a REGISTERED post-logout URI, for the same reason the authorize endpoint only
		// redirects to registered ones: otherwise this is an open redirect wearing a logout costume.
		if c, err := h.store.GetClient(r.Context(), clientID); err == nil {
			for _, u := range c.PostLogoutURIs {
				if u == redirect {
					http.Redirect(w, r, redirect, http.StatusFound)
					return
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func checkSecret(hash, presented string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(presented)) == nil
}
