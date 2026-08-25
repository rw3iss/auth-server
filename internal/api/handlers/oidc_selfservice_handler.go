package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rw3iss/auth/internal/api/middleware"
	"github.com/rw3iss/auth/internal/auth/oidc"
	apperrors "github.com/rw3iss/auth/pkg/shared/errors"
)

// OIDCSelfServiceHandler lets any authenticated member register and manage THEIR OWN relying parties —
// the "add Login with CivicGate to my site" path, the way Google and GitHub let any account register an
// OAuth application.
//
// ═══ WHY THIS IS SAFE WHEN THE ADMIN SURFACE IS ADMIN-ONLY ═══════════════════════════════════════════
//
// The administrative endpoints stay administrative, unchanged, because they can do things this one
// deliberately cannot. Everything that made client registration an operator capability is withheld here:
//
//	OWNERSHIP     every read and write filters on the caller's user id INSIDE the statement
//	              (oidc.Store's *ByOwner methods). Admin-created clients have a NULL owner and are
//	              therefore invisible and unreachable through this handler.
//	REDIRECTS     validated by the shared oidc.ValidateRedirectURIs — exact, absolute, https, with an
//	              exception only for a genuinely loopback host. This is the control the whole flow rests
//	              on; see internal/auth/oidc/redirect.go.
//	SCOPES        intersected with oidc.SelfServiceScopes (openid/profile/email). A self-registered
//	              client cannot award itself the civic:* scopes or offline_access.
//	TRUST         `trusted` is never settable, so a self-service client can never skip the consent
//	              screen; `require_pkce` is forced on; `app_code` is never settable, so it cannot scope
//	              its tokens to another application's namespace.
//	VOLUME        oidc.MaxClientsPerOwner per account, plus a per-account create rate limit here.
//	SECRET        returned exactly once, at creation and at rotation; the column holds a bcrypt hash and
//	              a short display prefix, and no endpoint can read the secret back.
//
// Error messages are written to be READ by the developer who hit them — particularly the redirect-URI
// reasons, which are the single most common thing to get wrong and the least self-evident.
type OIDCSelfServiceHandler struct {
	store *oidc.Store
	// Per-ACCOUNT, not per-IP: the caller is authenticated, so the account is the meaningful identity and
	// an attacker rotating IPs gains nothing. In-process is the right strength — the durable cap
	// (MaxClientsPerOwner) is enforced in the database; this only smooths bursts.
	createLimiter *ipLimiter
}

func NewOIDCSelfServiceHandler(store *oidc.Store) *OIDCSelfServiceHandler {
	return &OIDCSelfServiceHandler{
		store: store,
		// 10 creates/hour/account. Ten is already the lifetime cap, so anything faster than this is not a
		// person registering applications.
		createLimiter: newIPLimiter(10, time.Hour),
	}
}

// ownerID returns the authenticated caller's user id, or "" when there is none.
func ownerID(r *http.Request) string {
	id := middleware.GetUserID(r.Context())
	if id == nil {
		return ""
	}
	s := id.String()
	if s == "" || s == "00000000-0000-0000-0000-000000000000" {
		return ""
	}
	return s
}

// myClientDTO is the self-service view of a client. It is NOT the admin DTO: `trusted` and `app_code`
// are absent because they are not settable here, and printing a field a caller cannot change reads as an
// invitation to try.
type myClientDTO struct {
	ClientID       string   `json:"client_id"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	LogoURL        string   `json:"logo_url,omitempty"`
	RedirectURIs   []string `json:"redirect_uris"`
	PostLogoutURIs []string `json:"post_logout_uris"`
	AllowedScopes  []string `json:"allowed_scopes"`
	GrantTypes     []string `json:"grant_types"`
	Status         string   `json:"status"`
	RequirePKCE    bool     `json:"require_pkce"`
	// Whether a secret exists and its first characters — never the secret. It is shown once, at creation
	// or rotation, and the column holds only a hash.
	HasSecret    bool   `json:"has_secret"`
	SecretPrefix string `json:"client_secret_prefix,omitempty"`
	IsPublic     bool   `json:"is_public"`
	CreatedAt    string `json:"created_at,omitempty"`
}

func toMyDTO(c *oidc.Client) myClientDTO {
	d := myClientDTO{
		ClientID: c.ClientID, Name: c.Name,
		Description: c.Description.String, LogoURL: c.LogoURL.String,
		RedirectURIs: c.RedirectURIs, PostLogoutURIs: c.PostLogoutURIs,
		AllowedScopes: c.AllowedScopes, GrantTypes: c.GrantTypes,
		Status: c.Status, RequirePKCE: c.RequirePKCE,
		HasSecret: !c.IsPublic(), SecretPrefix: c.SecretPrefix.String, IsPublic: c.IsPublic(),
	}
	if d.RedirectURIs == nil {
		d.RedirectURIs = []string{}
	}
	if d.PostLogoutURIs == nil {
		d.PostLogoutURIs = []string{}
	}
	if d.AllowedScopes == nil {
		d.AllowedScopes = []string{}
	}
	if d.GrantTypes == nil {
		d.GrantTypes = []string{}
	}
	if !c.CreatedAt.IsZero() {
		d.CreatedAt = c.CreatedAt.UTC().Format(time.RFC3339)
	}
	return d
}

// notFound is the single answer for "no such client" AND "not yours".
//
// One response for both, deliberately: a distinguishable "forbidden" would confirm that a client id
// exists, which is an enumeration oracle over every registered application on the platform.
func notFound() *apperrors.AppError {
	return apperrors.NotFound("Application")
}

// List handles GET /oidc/clients — the caller's OWN clients only.
func (h *OIDCSelfServiceHandler) List(w http.ResponseWriter, r *http.Request) {
	owner := ownerID(r)
	if owner == "" {
		writeError(w, apperrors.Unauthorized("Sign in to manage your applications"))
		return
	}
	rows, err := h.store.ListClientsByOwner(r.Context(), owner)
	if err != nil {
		writeError(w, apperrors.Internal("Could not list your applications"))
		return
	}
	out := make([]myClientDTO, 0, len(rows))
	for _, c := range rows {
		out = append(out, toMyDTO(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"clients":           out,
		"allowed_scopes":    oidc.SelfServiceScopes,
		"max_clients":       oidc.MaxClientsPerOwner,
		"max_redirect_uris": oidc.MaxRedirectURIs,
	})
}

// Get handles GET /oidc/clients/{clientId} — own only.
func (h *OIDCSelfServiceHandler) Get(w http.ResponseWriter, r *http.Request) {
	owner := ownerID(r)
	if owner == "" {
		writeError(w, apperrors.Unauthorized("Sign in to manage your applications"))
		return
	}
	c, err := h.store.GetClientByOwner(r.Context(), r.PathValue("clientId"), owner)
	if err != nil {
		if errors.Is(err, oidc.ErrClientNotFound) {
			writeError(w, notFound())
			return
		}
		writeError(w, apperrors.Internal("Could not load that application"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client": toMyDTO(c)})
}

type createMyClientRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	LogoURL        string   `json:"logo_url"`
	RedirectURIs   []string `json:"redirect_uris"`
	PostLogoutURIs []string `json:"post_logout_uris"`
	AllowedScopes  []string `json:"allowed_scopes"`
	// A public client (SPA / mobile) gets no secret; PKCE protects it instead.
	Public bool `json:"public"`
}

// Create handles POST /oidc/clients. Returns the secret EXACTLY ONCE.
func (h *OIDCSelfServiceHandler) Create(w http.ResponseWriter, r *http.Request) {
	owner := ownerID(r)
	if owner == "" {
		writeError(w, apperrors.Unauthorized("Sign in to register an application"))
		return
	}
	var req createMyClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apperrors.InvalidInput("body", "Invalid request body"))
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, apperrors.InvalidInput("name", "Give your application a name — people see it on the consent screen"))
		return
	}
	if len(name) > 100 {
		writeError(w, apperrors.InvalidInput("name", "Application names must be 100 characters or fewer"))
		return
	}
	if len(req.Description) > 500 {
		writeError(w, apperrors.InvalidInput("description", "Descriptions must be 500 characters or fewer"))
		return
	}
	if msg := validateLogoURL(req.LogoURL); msg != "" {
		writeError(w, apperrors.InvalidInput("logo_url", msg))
		return
	}

	redirects := oidc.NormalizeURIs(req.RedirectURIs)
	if msg := oidc.ValidateRedirectURIs(redirects); msg != "" {
		writeError(w, apperrors.InvalidInput("redirect_uris", msg))
		return
	}
	postLogout := oidc.NormalizeURIs(req.PostLogoutURIs)
	if msg := oidc.ValidatePostLogoutURIs(postLogout); msg != "" {
		writeError(w, apperrors.InvalidInput("post_logout_uris", msg))
		return
	}

	scopes, msg := resolveSelfServiceScopes(req.AllowedScopes)
	if msg != "" {
		writeError(w, apperrors.InvalidInput("allowed_scopes", msg))
		return
	}

	// Rate limit AFTER validation, so a developer fixing a typo does not burn their hourly budget on
	// requests that never created anything.
	if !h.createLimiter.allow(owner) {
		writeError(w, apperrors.RateLimited())
		return
	}

	// Grant types are fixed. authorization_code is what this handler exists to enable; refresh_token is
	// harmless without offline_access, which self-service clients cannot request. client_credentials is
	// deliberately absent — that grant authenticates a SERVICE, not a person, and belongs to the
	// administratively-issued M2M registry.
	// FIXED, and deliberately not caller-settable — unlike the admin path, which now validates a chosen
	// list. A self-service registrant may not grant themselves client_credentials: that grant
	// authenticates a SERVICE with no user present, and handing it out on self-service registration would
	// let any member mint an application principal. Administratively-issued clients can have it.
	grants := oidc.DefaultGrants
	in := oidc.ClientInput{
		Name: &name, Description: &req.Description, LogoURL: &req.LogoURL,
		RedirectURIs: &redirects, PostLogoutURIs: &postLogout,
		AllowedScopes: &scopes, GrantTypes: &grants,
	}

	// The server mints the id — see oidc.MintClientID. Retried once on the (vanishingly unlikely)
	// collision with an existing id, since the random suffix is what makes it unique.
	var clientID, secret string
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		clientID, err = oidc.MintClientID(name)
		if err != nil {
			writeError(w, apperrors.Internal("Could not register the application"))
			return
		}
		secret, err = h.store.CreateOwnedClient(r.Context(), clientID, in, owner, req.Public)
		if err == nil || !strings.Contains(err.Error(), "duplicate key") {
			break
		}
	}
	if err != nil {
		if errors.Is(err, oidc.ErrClientLimitReached) {
			writeError(w, apperrors.InvalidInput("client",
				"You already have the maximum number of applications. Delete one you no longer use to register another."))
			return
		}
		writeError(w, apperrors.Internal("Could not register the application"))
		return
	}

	resp := map[string]any{
		"client_id": clientID,
		"name":      name,
	}
	if req.Public {
		resp["is_public"] = true
		resp["note"] = "Public clients get no secret. PKCE is required and is what protects the flow."
	} else {
		// Shown once. There is no endpoint that returns it again — only rotation, which invalidates the old.
		resp["client_secret"] = secret
		resp["warning"] = "Copy the client secret now. It cannot be shown again."
	}
	writeJSON(w, http.StatusCreated, resp)
}

// Update handles PATCH /oidc/clients/{clientId} — own only.
func (h *OIDCSelfServiceHandler) Update(w http.ResponseWriter, r *http.Request) {
	owner := ownerID(r)
	if owner == "" {
		writeError(w, apperrors.Unauthorized("Sign in to manage your applications"))
		return
	}
	clientID := r.PathValue("clientId")

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeError(w, apperrors.InvalidInput("body", "Invalid request body"))
		return
	}

	// Only these keys are read. `trusted`, `require_pkce`, `app_code` and `grant_types` are not in the
	// list and are not in UpdateClientByOwner's SET clause either — belt and braces, because this is the
	// exact place a future edit would accidentally widen.
	in := oidc.ClientInput{}
	if p, ok, bad := optString(raw, "name", 100); bad != "" {
		writeError(w, apperrors.InvalidInput("name", bad))
		return
	} else if ok {
		if strings.TrimSpace(*p) == "" {
			writeError(w, apperrors.InvalidInput("name", "Give your application a name — people see it on the consent screen"))
			return
		}
		trimmed := strings.TrimSpace(*p)
		in.Name = &trimmed
	}
	if p, ok, bad := optString(raw, "description", 500); bad != "" {
		writeError(w, apperrors.InvalidInput("description", bad))
		return
	} else if ok {
		in.Description = p
	}
	if p, ok, bad := optString(raw, "logo_url", 512); bad != "" {
		writeError(w, apperrors.InvalidInput("logo_url", bad))
		return
	} else if ok {
		if msg := validateLogoURL(*p); msg != "" {
			writeError(w, apperrors.InvalidInput("logo_url", msg))
			return
		}
		in.LogoURL = p
	}

	// VALIDATED ON UPDATE EXACTLY AS ON CREATE. A rule enforced only at creation is not a rule — the edit
	// form would be the way around it.
	if s, ok := optSlice(raw, "redirect_uris"); ok {
		norm := oidc.NormalizeURIs(s)
		if msg := oidc.ValidateRedirectURIs(norm); msg != "" {
			writeError(w, apperrors.InvalidInput("redirect_uris", msg))
			return
		}
		in.RedirectURIs = &norm
	}
	if s, ok := optSlice(raw, "post_logout_uris"); ok {
		norm := oidc.NormalizeURIs(s)
		if msg := oidc.ValidatePostLogoutURIs(norm); msg != "" {
			writeError(w, apperrors.InvalidInput("post_logout_uris", msg))
			return
		}
		in.PostLogoutURIs = &norm
	}
	if s, ok := optSlice(raw, "allowed_scopes"); ok {
		scopes, msg := resolveSelfServiceScopes(s)
		if msg != "" {
			writeError(w, apperrors.InvalidInput("allowed_scopes", msg))
			return
		}
		in.AllowedScopes = &scopes
	}
	// Status is restricted to the two values an owner may legitimately choose. Both are narrower than or
	// equal to what the client already has: disabling revokes it, active restores its own prior state.
	if p, ok, bad := optString(raw, "status", 16); bad != "" {
		writeError(w, apperrors.InvalidInput("status", bad))
		return
	} else if ok {
		v := strings.TrimSpace(strings.ToLower(*p))
		if v != "active" && v != "disabled" {
			writeError(w, apperrors.InvalidInput("status", `Status must be "active" or "disabled"`))
			return
		}
		in.Status = &v
	}

	if err := h.store.UpdateClientByOwner(r.Context(), clientID, owner, in); err != nil {
		if errors.Is(err, oidc.ErrClientNotFound) {
			writeError(w, notFound())
			return
		}
		writeError(w, apperrors.Internal("Could not update that application"))
		return
	}
	c, err := h.store.GetClientByOwner(r.Context(), clientID, owner)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated", "client": toMyDTO(c)})
}

// RotateSecret handles POST /oidc/clients/{clientId}/rotate-secret — own only.
func (h *OIDCSelfServiceHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	owner := ownerID(r)
	if owner == "" {
		writeError(w, apperrors.Unauthorized("Sign in to manage your applications"))
		return
	}
	secret, err := h.store.RotateSecretByOwner(r.Context(), r.PathValue("clientId"), owner)
	if err != nil {
		if errors.Is(err, oidc.ErrClientNotFound) {
			writeError(w, notFound())
			return
		}
		writeError(w, apperrors.Internal("Could not rotate the secret"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"client_secret": secret,
		"warning":       "The previous secret stopped working immediately. Copy this one now — it cannot be shown again.",
	})
}

// Delete handles DELETE /oidc/clients/{clientId} — own only.
func (h *OIDCSelfServiceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	owner := ownerID(r)
	if owner == "" {
		writeError(w, apperrors.Unauthorized("Sign in to manage your applications"))
		return
	}
	if err := h.store.DeleteClientByOwner(r.Context(), r.PathValue("clientId"), owner); err != nil {
		if errors.Is(err, oidc.ErrClientNotFound) {
			writeError(w, notFound())
			return
		}
		writeError(w, apperrors.Internal("Could not delete that application"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ── Input helpers ────────────────────────────────────────────────────────────────────────────────────

// resolveSelfServiceScopes intersects a request with oidc.SelfServiceScopes.
//
// It REJECTS an out-of-range scope rather than silently dropping it. A silent drop would leave the
// developer with a client that authorises fine and then returns a token missing the claim they asked
// for, with nothing anywhere explaining why — the kind of failure that costs a day.
func resolveSelfServiceScopes(requested []string) ([]string, string) {
	if len(requested) == 0 {
		return append([]string{}, oidc.SelfServiceScopes...), ""
	}
	allowed := map[string]bool{}
	for _, s := range oidc.SelfServiceScopes {
		allowed[s] = true
	}
	out := []string{oidc.ScopeOpenID}
	seen := map[string]bool{oidc.ScopeOpenID: true}
	for _, raw := range requested {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !allowed[s] {
			return nil, "A self-registered application may request only these scopes: " +
				strings.Join(oidc.SelfServiceScopes, ", ") + `. "` + truncate(s, 40) +
				`" is granted by a CivicGate administrator — contact us if your application needs it.`
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, ""
}

// validateLogoURL keeps the consent screen from rendering an attacker-chosen image over plain http, and
// keeps a javascript:/data: URL out of an <img src> on our own origin.
func validateLogoURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if len(s) > 512 {
		return "Logo URLs must be 512 characters or fewer"
	}
	if !strings.HasPrefix(strings.ToLower(s), "https://") {
		return "Logo URLs must start with https://"
	}
	return ""
}

// optString reads an optional JSON string. Returns (value, present, errorMessage).
func optString(raw map[string]json.RawMessage, key string, max int) (*string, bool, string) {
	msg, ok := raw[key]
	if !ok {
		return nil, false, ""
	}
	var v string
	if err := json.Unmarshal(msg, &v); err != nil {
		return nil, false, "Expected a text value"
	}
	if len(v) > max {
		return nil, false, "That value is too long"
	}
	return &v, true, ""
}

// optSlice reads an optional JSON array of strings. A key present but not an array is treated as absent
// rather than as an error, matching the admin handler's tolerance.
func optSlice(raw map[string]json.RawMessage, key string) ([]string, bool) {
	msg, ok := raw[key]
	if !ok {
		return nil, false
	}
	var v []string
	if err := json.Unmarshal(msg, &v); err != nil {
		return nil, false
	}
	if v == nil {
		v = []string{}
	}
	return v, true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
