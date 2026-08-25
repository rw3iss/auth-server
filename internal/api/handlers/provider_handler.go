package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// The IDENTITY OF THIS AUTH SERVER, as a relying party's UI should render it.
//
// ONE PROVIDER PER INSTALLATION. This server IS the OIDC/FedCM provider — there is no registry of
// providers to choose from, and adding one would be a different product. So the identity is deployment
// configuration, not data: an installation at auth.civicgate.org is "CivicGate", one at
// auth-demo.rw3iss.com is whatever that deployment calls itself.
//
// WHY IT IS SERVED RATHER THAN HARD-CODED IN EACH CLIENT: every sign-in surface needs the same name and
// icon — the hosted login page, the SDK's "Sign in with …" button, an embedded widget on a third-party
// site, the FedCM account chooser the BROWSER paints. Copying those strings into each client is how a
// rename ends up half-applied, with one surface still advertising the old name. Clients fetch this once
// and render it.
type ProviderIdentity struct {
	// Stable machine identifier ("civic-gate"). Never shown to a user; safe to key cache entries on.
	Slug string `json:"slug"`
	// Full display name ("CivicGate", "Test Organization Name").
	Name string `json:"name"`
	// Optional abbreviated name for tight layouts ("CivicGate" → "CivicGate"; "Test Organization Name" →
	// "TestOrgName"). A CLIENT decides when to use it — the server only says what it is, because only the
	// client knows how much room it has.
	ShortName string `json:"shortName,omitempty"`
	// Absolute URL. Absolute because it is rendered on origins that are not this one.
	IconURL string `json:"iconUrl,omitempty"`
	// Chooser/button colours; also fed to FedCM branding so the browser dialog matches the buttons.
	BackgroundColor string `json:"backgroundColor,omitempty"`
	Color           string `json:"color,omitempty"`
	// The issuer, so a client can discover OIDC/FedCM without being told separately.
	Issuer string `json:"issuer,omitempty"`
	// What this deployment actually supports, so a client can render only what will work rather than
	// showing a button that fails. Absence is meaningful: no `fedcm` here means do not attempt it.
	Methods []string `json:"methods"`
}

// DefaultProviderIdentity is the generic fallback. Deliberately NOT "CivicGate": a fresh installation that
// has not been configured should not advertise somebody else's brand — it should look unconfigured, which
// is a fixable state, rather than wrong, which is not noticed.
func DefaultProviderIdentity(issuer string) ProviderIdentity {
	return ProviderIdentity{
		Slug:    "auth",
		Name:    "Auth Server",
		Issuer:  issuer,
		Methods: []string{"password"},
	}
}

// ProviderIdentityFromEnv reads the deployment's identity.
//
// FALLBACK CHAIN, most specific first: AUTH_PROVIDER_* → the FEDCM_BRAND_* vars that already existed →
// the default. The FedCM vars are honoured so an installation configured before this existed keeps its
// name instead of silently reverting to "Auth Server".
func ProviderIdentityFromEnv(issuer string, fedcmAvailable, oidcAvailable bool) ProviderIdentity {
	p := DefaultProviderIdentity(issuer)

	if v := firstNonEmpty(os.Getenv("AUTH_PROVIDER_NAME"), os.Getenv("FEDCM_BRAND_NAME")); v != "" {
		p.Name = v
	}
	if v := os.Getenv("AUTH_PROVIDER_SLUG"); v != "" {
		p.Slug = v
	} else if p.Name != "" {
		// Derive a slug rather than requiring one: a deployment that sets only a name still gets a stable
		// key, and a derived slug is better than an operator inventing an inconsistent one.
		p.Slug = slugify(p.Name)
	}
	if v := os.Getenv("AUTH_PROVIDER_SHORT_NAME"); v != "" {
		p.ShortName = v
	}
	if v := firstNonEmpty(os.Getenv("AUTH_PROVIDER_ICON_URL"), os.Getenv("FEDCM_BRAND_ICON_URL")); v != "" {
		p.IconURL = v
	}
	if v := firstNonEmpty(os.Getenv("AUTH_PROVIDER_BACKGROUND"), os.Getenv("FEDCM_BRAND_BACKGROUND")); v != "" {
		p.BackgroundColor = v
	}
	if v := firstNonEmpty(os.Getenv("AUTH_PROVIDER_COLOR"), os.Getenv("FEDCM_BRAND_COLOR")); v != "" {
		p.Color = v
	}

	// Reported from what is actually wired, never from configuration intent: a client that renders a
	// "Sign in with X" button for a method this deployment cannot serve produces a dead button and a
	// support ticket.
	methods := []string{"password"}
	if oidcAvailable {
		methods = append(methods, "oidc")
	}
	if fedcmAvailable {
		methods = append(methods, "fedcm")
	}
	p.Methods = methods
	return p
}

// ProviderHandler serves the identity to any client that needs to render it.
type ProviderHandler struct{ identity ProviderIdentity }

func NewProviderHandler(p ProviderIdentity) *ProviderHandler { return &ProviderHandler{identity: p} }

// Get is PUBLIC and CORS-open on purpose: it carries no secret, and the surfaces that need it include
// widgets on origins this server has never heard of. Refusing them would mean every embedder must proxy
// a public logo and name.
func (h *ProviderHandler) Get(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// Cacheable: it changes when a deployment is reconfigured, which is rare, and every sign-in surface
	// asks for it.
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(h.identity)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// slugify is intentionally minimal — it produces a key, not a URL segment users type.
func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
