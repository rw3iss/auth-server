package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rw3iss/auth/internal/auth/oidc"
	"github.com/rw3iss/auth/pkg/shared/errors"
)

// OIDCAdminHandler is CRUD over registered relying parties, for the admin UI.
//
// Every route here is behind the admin chain. That matters more than usual: a write to this table decides
// where authorization codes may be delivered and what a client may ever read. Registering a redirect_uri
// is functionally granting someone the ability to receive other people's sessions, so this is an
// administrative capability, not a self-service one.
type OIDCAdminHandler struct{ store *oidc.Store }

func NewOIDCAdminHandler(store *oidc.Store) *OIDCAdminHandler { return &OIDCAdminHandler{store: store} }

type clientDTO struct {
	ClientID       string   `json:"client_id"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	LogoURL        string   `json:"logo_url,omitempty"`
	RedirectURIs   []string `json:"redirect_uris"`
	PostLogoutURIs []string `json:"post_logout_uris"`
	AllowedScopes  []string `json:"allowed_scopes"`
	GrantTypes     []string `json:"grant_types"`
	AppCode        string   `json:"app_code,omitempty"`
	Trusted        bool     `json:"trusted"`
	RequirePKCE    bool     `json:"require_pkce"`
	Status         string   `json:"status"`
	// Whether a secret exists — never the secret itself. It is shown once, at creation or rotation.
	HasSecret bool `json:"has_secret"`
	IsPublic  bool `json:"is_public"`
}

func toDTO(c *oidc.Client) clientDTO {
	return clientDTO{
		ClientID: c.ClientID, Name: c.Name,
		Description: c.Description.String, LogoURL: c.LogoURL.String,
		RedirectURIs: c.RedirectURIs, PostLogoutURIs: c.PostLogoutURIs,
		AllowedScopes: c.AllowedScopes, GrantTypes: c.GrantTypes,
		AppCode: c.AppCode.String, Trusted: c.Trusted, RequirePKCE: c.RequirePKCE,
		Status: c.Status, HasSecret: !c.IsPublic(), IsPublic: c.IsPublic(),
	}
}

// List handles GET /admin/oauth/clients.
func (h *OIDCAdminHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.ListClients(r.Context())
	if err != nil {
		writeError(w, errors.Internal("Could not list clients"))
		return
	}
	out := make([]clientDTO, 0, len(rows))
	for _, c := range rows {
		out = append(out, toDTO(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out, "supported_scopes": oidc.SupportedScopes})
}

type createOIDCClientRequest struct {
	ClientID       string   `json:"client_id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	LogoURL        string   `json:"logo_url"`
	RedirectURIs   []string `json:"redirect_uris"`
	PostLogoutURIs []string `json:"post_logout_uris"`
	AllowedScopes  []string `json:"allowed_scopes"`
	AppCode        string   `json:"app_code"`
	Trusted        bool     `json:"trusted"`
	RequirePKCE    *bool    `json:"require_pkce"`
	// A public client (SPA / mobile) gets no secret; PKCE protects it instead.
	Public bool `json:"public"`
	// Which grants this application may use. Omitted → authorization_code + refresh_token, which is what
	// an interactive application needs and nothing more. An administrator may add client_credentials here
	// for a server-to-server application; self-service registration cannot (see the self-service handler).
	GrantTypes []string `json:"grant_types"`
}

// Create handles POST /admin/oauth/clients. Returns the secret EXACTLY ONCE.
func (h *OIDCAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createOIDCClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.ClientID == "" || strings.TrimSpace(req.Name) == "" {
		writeError(w, errors.InvalidInput("client_id", "client_id and name are required"))
		return
	}
	if len(req.RedirectURIs) == 0 {
		// Refuse rather than create a client that cannot complete a login — the operator would otherwise
		// discover this only when the first user hits a redirect error.
		writeError(w, errors.InvalidInput("redirect_uris", "At least one redirect URI is required"))
		return
	}
	if bad := validateRedirects(req.RedirectURIs); bad != "" {
		writeError(w, errors.InvalidInput("redirect_uris", bad))
		return
	}
	if len(req.AllowedScopes) == 0 {
		req.AllowedScopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}
	}
	if !contains(req.AllowedScopes, oidc.ScopeOpenID) {
		req.AllowedScopes = append([]string{oidc.ScopeOpenID}, req.AllowedScopes...)
	}

	in := oidc.ClientInput{
		Name: &req.Name, Description: &req.Description, LogoURL: &req.LogoURL,
		RedirectURIs: &req.RedirectURIs, PostLogoutURIs: &req.PostLogoutURIs,
		AllowedScopes: &req.AllowedScopes, AppCode: &req.AppCode,
		Trusted: &req.Trusted, RequirePKCE: req.RequirePKCE,
	}
	// GRANTS ARE NOW CHOSEN AND VALIDATED, not hardcoded.
	//
	// They used to be fixed here at authorization_code + refresh_token, which meant the stored column
	// could never say anything else through this endpoint — while PATCH accepted any array at all and
	// nothing enforced either. Validating at the write is what makes `AllowsGrant` meaningful: a typo, or
	// a grant this server does not implement, is refused now rather than producing a client that can
	// never obtain a token and gives no clue why.
	// Scopes are validated against what this server implements, for the same reason grants are: an
	// unknown scope stored here is one a consent screen will show and a token will never carry.
	for _, sc := range req.AllowedScopes {
		if !oidc.IsSupportedScope(sc) {
			writeError(w, errors.InvalidInput("allowed_scopes", "Unsupported scope: "+sc))
			return
		}
	}

	grants := oidc.DefaultGrants
	if len(req.GrantTypes) > 0 {
		for _, g := range req.GrantTypes {
			if !oidc.IsSupportedGrant(g) {
				writeError(w, errors.InvalidInput("grant_types", "Unsupported grant type: "+g))
				return
			}
		}
		grants = req.GrantTypes
	}
	// client_credentials authenticates the APPLICATION, so it needs a secret to authenticate with. On a
	// public client the grant would hand a service token to anyone holding a client id that is published
	// by design.
	if req.Public {
		for _, g := range grants {
			if g == oidc.GrantClientCredentials {
				writeError(w, errors.InvalidInput("grant_types", "client_credentials requires a confidential client; do not set public"))
				return
			}
		}
	}
	in.GrantTypes = &grants

	secret, err := h.store.CreateClient(r.Context(), req.ClientID, in, req.Public)
	if err != nil {
		// Report the actual cause. The previous blanket "the id may already exist" was a guess, and it
		// sent an operator hunting for a duplicate that was not there when the real fault was a bad column.
		if strings.Contains(err.Error(), "duplicate key") {
			writeError(w, errors.InvalidInput("client_id", "That client_id is already registered"))
			return
		}
		writeError(w, errors.InvalidInput("client_id", "Could not create client: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": req.ClientID,
		// Shown once. There is no endpoint that returns it again — only rotation, which invalidates the old.
		"client_secret": secret,
		"warning":       "Copy the client secret now. It cannot be shown again.",
	})
}

// Update handles PATCH /admin/oauth/clients/{clientId}.
func (h *OIDCAdminHandler) Update(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("clientId")
	var req map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errors.InvalidInput("body", "Invalid request body"))
		return
	}
	in := oidc.ClientInput{}
	str := func(k string) *string {
		raw, ok := req[k]
		if !ok {
			return nil
		}
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return nil
		}
		return &v
	}
	slice := func(k string) *[]string {
		raw, ok := req[k]
		if !ok {
			return nil
		}
		var v []string
		if json.Unmarshal(raw, &v) != nil {
			return nil
		}
		return &v
	}
	boolp := func(k string) *bool {
		raw, ok := req[k]
		if !ok {
			return nil
		}
		var v bool
		if json.Unmarshal(raw, &v) != nil {
			return nil
		}
		return &v
	}
	in.Name, in.Description, in.LogoURL = str("name"), str("description"), str("logo_url")
	in.AppCode, in.Status = str("app_code"), str("status")
	in.RedirectURIs, in.PostLogoutURIs = slice("redirect_uris"), slice("post_logout_uris")
	in.AllowedScopes, in.GrantTypes = slice("allowed_scopes"), slice("grant_types")
	in.Trusted, in.RequirePKCE = boolp("trusted"), boolp("require_pkce")

	// PATCH validates the same way CREATE does. It previously accepted ANY array — including grants this
	// server does not implement — because nothing read the column afterwards. Now that AllowsGrant
	// enforces it, an unvalidated write here is a way to lock a working client out of its own grant.
	if in.GrantTypes != nil {
		wantsClientCreds := false
		for _, g := range *in.GrantTypes {
			if !oidc.IsSupportedGrant(g) {
				writeError(w, errors.InvalidInput("grant_types", "Unsupported grant type: "+g))
				return
			}
			if g == oidc.GrantClientCredentials {
				wantsClientCreds = true
			}
		}
		// CREATE refuses client_credentials on a public client; PATCH has to as well, and could not
		// before because it never loaded the row and so could not tell whether it was public. The token
		// endpoint does refuse a public client at request time, so this was never exploitable — but the
		// stored column would claim a capability the client does not have, and a settings screen that
		// lies about what is enabled is its own kind of defect.
		if wantsClientCreds {
			existing, err := h.store.GetClient(r.Context(), clientID)
			if err != nil {
				writeError(w, errors.NotFound("client"))
				return
			}
			if existing.IsPublic() {
				writeError(w, errors.InvalidInput("grant_types", "client_credentials requires a confidential client; this client is public"))
				return
			}
		}
	}

	if in.RedirectURIs != nil {
		if len(*in.RedirectURIs) == 0 {
			writeError(w, errors.InvalidInput("redirect_uris", "At least one redirect URI is required"))
			return
		}
		if bad := validateRedirects(*in.RedirectURIs); bad != "" {
			writeError(w, errors.InvalidInput("redirect_uris", bad))
			return
		}
	}
	if err := h.store.UpdateClient(r.Context(), clientID, in); err != nil {
		writeError(w, errors.Internal("Could not update client"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// RotateSecret handles POST /admin/oauth/clients/{clientId}/rotate-secret.
func (h *OIDCAdminHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	secret, err := h.store.RotateSecret(r.Context(), r.PathValue("clientId"))
	if err != nil {
		writeError(w, errors.Internal("Could not rotate the secret"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"client_secret": secret,
		"warning":       "The previous secret stopped working immediately. Copy this one now.",
	})
}

// Delete handles DELETE /admin/oauth/clients/{clientId}.
func (h *OIDCAdminHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.store.DeleteClient(r.Context(), r.PathValue("clientId")); err != nil {
		writeError(w, errors.Internal("Could not delete client"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// validateRedirects rejects the shapes that make an allow-list useless.
//
// Delegates to the shared oidc.ValidateRedirectURIs so the administrative and the self-service
// registration paths cannot drift — a rule this sharp kept in two places eventually disagrees, and the
// disagreement is a hole rather than a bug.
//
// This is strictly a TIGHTENING of the admin path, never a relaxation. The rule it replaced tested
// `strings.HasPrefix(s, "http://localhost")`, which also accepts "http://localhost.attacker.net/cb" —
// an ordinary registrable domain, over plain http, that would receive every authorization code issued
// to that client. The shared validator compares the PARSED HOST instead.
func validateRedirects(uris []string) string {
	return oidc.ValidateRedirectURIs(uris)
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
