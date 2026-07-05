package domain

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/ven/auth/pkg/shared/models"
	"github.com/ven/auth/pkg/shared/types"
)

// WebhookEventUserRegistered fires when a NEW user is created through an
// app (plain register, or the register side of register_or_login /
// register_or_return; never for logins of existing users).
const WebhookEventUserRegistered = "user.registered"

// KnownWebhookEvents enumerates dispatchable event types. Extend here +
// at the dispatch call sites when new events are added.
var KnownWebhookEvents = []string{WebhookEventUserRegistered}

// AppWebhook is one outbound webhook config on an app (migration 019).
// Stored as JSONB inside apps.webhooks.
type AppWebhook struct {
	// Name is an operator label ("Slack #signups"). Optional.
	Name string `json:"name,omitempty"`
	// URL receives a POST with the JSON event envelope. URLs under
	// hooks.slack.com instead get a Slack-formatted {"text": ...} body.
	URL string `json:"url"`
	// Events this hook subscribes to (see KnownWebhookEvents).
	Events []string `json:"events"`
	// Enabled toggles dispatch without deleting the config.
	Enabled bool `json:"enabled"`
}

// SubscribesTo reports whether the hook is enabled and lists the event.
func (w AppWebhook) SubscribesTo(event string) bool {
	if !w.Enabled {
		return false
	}
	for _, e := range w.Events {
		if e == event {
			return true
		}
	}
	return false
}

// AppWebhooks is the JSONB array column type for apps.webhooks.
type AppWebhooks []AppWebhook

// Value implements driver.Valuer — marshals to JSONB.
func (w AppWebhooks) Value() (driver.Value, error) {
	if w == nil {
		return "[]", nil
	}
	b, err := json.Marshal(w)
	return string(b), err
}

// Scan implements sql.Scanner — unmarshals from JSONB.
func (w *AppWebhooks) Scan(src any) error {
	if src == nil {
		*w = AppWebhooks{}
		return nil
	}
	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("unsupported type for AppWebhooks: %T", src)
	}
	if len(b) == 0 {
		*w = AppWebhooks{}
		return nil
	}
	return json.Unmarshal(b, w)
}

// App represents a consuming application of the Vendidit auth system.
// One row per app — registered once by a system_admin (see
// docs/APP_REGISTRATION.md).
//
// Storage notes:
//   - AllowedRedirectURLs / ServiceCodes are TEXT[] in Postgres; we lean
//     on lib/pq's pq.StringArray for the round trip.
//   - Status is a string column so we can extend it later (e.g. "suspended")
//     without a schema migration.
type App struct {
	models.BaseModel
	models.SoftDeletable

	Code                string         `db:"code" json:"code"`
	Name                string         `db:"name" json:"name"`
	Description         string         `db:"description" json:"description"`
	AllowedRedirectURLs pq.StringArray `db:"allowed_redirect_urls" json:"allowed_redirect_urls"`
	ServiceCodes        pq.StringArray `db:"service_codes" json:"service_codes"`
	AutoGrantOnSignup   bool           `db:"auto_grant_on_signup" json:"auto_grant_on_signup"`
	Status              string         `db:"status" json:"status"`
	Metadata            []byte         `db:"metadata" json:"-"`

	// Registration policy — migration 013.
	//
	// AllowedEmailDomains restricts who may register through this app
	// to senders of one of the listed domains (case-insensitive match
	// against the part after '@'). Empty = any domain allowed.
	AllowedEmailDomains pq.StringArray `db:"allowed_email_domains" json:"allowed_email_domains"`

	// AllowedAuthMethods enumerates the credential mechanisms the app
	// accepts. Values: "password", "google", "apple", "microsoft",
	// "github", "custom". Empty = any enabled method on the server.
	AllowedAuthMethods pq.StringArray `db:"allowed_auth_methods" json:"allowed_auth_methods"`

	// DefaultOrganizationID is the org new registrants are auto-added
	// to on success (with role "org_member" via the existing membership
	// path). NULL = no auto-membership; users register without an org
	// and pick one later.
	DefaultOrganizationID *types.ID `db:"default_organization_id" json:"default_organization_id,omitempty"`

	// FrontendURL is the app's canonical client origin, e.g.
	// "https://auth-demo.vendidit.com". Used by the email layer to
	// construct verify / reset / magic-link / invitation URLs that
	// point back at the originating app instead of a global default.
	// NULL = fall back to the CLIENT_URL env var (single-tenant mode).
	FrontendURL *string `db:"frontend_url" json:"frontend_url,omitempty"`

	// User pools — migrations 017 + 018 / docs/USER_POOLS.md. Model:
	// ONE "default pool (registration)" + N "other pools (login)".
	//
	// RegistrationNamespace is the DEFAULT pool: new registrants get it
	// as their home namespace (users.namespace). NULL/empty ⇒
	// DefaultNamespace. Use WriteNamespace() for the resolved value.
	RegistrationNamespace *string `db:"registration_namespace" json:"registration_namespace,omitempty"`

	// RegistrationNamespaces — legacy ordered multi-write list from the
	// original migration-018 shape; kept for back-compat. When
	// non-empty its FIRST entry acts as the default pool (it wins over
	// the singular field). New configs should use the singular
	// RegistrationNamespace + ReadNamespaces instead.
	RegistrationNamespaces pq.StringArray `db:"registration_namespaces" json:"registration_namespaces"`

	// ReadNamespaces is the OTHER pools (login) set: pools this app
	// authenticates users against at login, beyond the default pool —
	// AND the pools new registrants are tagged into (user_namespaces).
	// Empty ⇒ just the default pool. The default pool is always
	// implicitly included. Use EffectiveReadNamespaces() for the
	// resolved [default, ...others] list.
	ReadNamespaces pq.StringArray `db:"read_namespaces" json:"read_namespaces"`

	// Webhooks — migration 019. Outbound hooks dispatched async on
	// matching events for this app (e.g. user.registered).
	Webhooks AppWebhooks `db:"webhooks" json:"webhooks"`

	// Auto-provisioning config — migration 020 (§7).
	//
	// DefaultRoleCode is the org role granted to users provisioned through
	// this app in DefaultOrganizationID (replaces the hardcoded org_member).
	// NULL/empty ⇒ org_member. Must be an org-scoped role; platform roles
	// (system_admin / super_admin / base_user) are rejected at provision time.
	DefaultRoleCode *string `db:"default_role_code" json:"default_role_code,omitempty"`

	// LinkedAppCodes are additional app codes whose user_apps membership is
	// also granted when this app provisions a user (e.g. globalsku →
	// vendidit-marketplace). Empty ⇒ none. Unknown codes are skipped with a
	// warning at provision time, never fatal.
	LinkedAppCodes pq.StringArray `db:"linked_app_codes" json:"linked_app_codes"`
}

// DefaultRole returns the org role code to grant in the app's default org,
// falling back to "org_member" when unset. Caller still validates the role is
// org-scoped before assigning.
func (a *App) DefaultRole() string {
	if a == nil || a.DefaultRoleCode == nil {
		return "org_member"
	}
	if s := strings.TrimSpace(*a.DefaultRoleCode); s != "" {
		return s
	}
	return "org_member"
}

// WebhooksFor returns the enabled webhooks subscribed to the event.
func (a *App) WebhooksFor(event string) []AppWebhook {
	if a == nil {
		return nil
	}
	var out []AppWebhook
	for _, w := range a.Webhooks {
		if w.SubscribesTo(event) {
			out = append(out, w)
		}
	}
	return out
}

// FrontendBaseURL returns the app's frontend URL or empty string when
// unset. Callers should treat "" as "no app-specific URL — fall back
// to the global default".
func (a *App) FrontendBaseURL() string {
	if a == nil || a.FrontendURL == nil {
		return ""
	}
	return *a.FrontendURL
}

// IsEmailDomainAllowed reports whether the given email passes this
// app's domain policy. Empty AllowedEmailDomains means "any domain"
// — the policy is opt-in. Comparison is case-insensitive and only
// looks at the part after '@'.
func (a *App) IsEmailDomainAllowed(email string) bool {
	if len(a.AllowedEmailDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, allowed := range a.AllowedEmailDomains {
		if strings.ToLower(string(allowed)) == domain {
			return true
		}
	}
	return false
}

// IsAuthMethodAllowed reports whether the given auth method (e.g.
// "password", "google") passes this app's policy. Empty
// AllowedAuthMethods means "any enabled method".
func (a *App) IsAuthMethodAllowed(method string) bool {
	if len(a.AllowedAuthMethods) == 0 {
		return true
	}
	m := strings.ToLower(method)
	for _, allowed := range a.AllowedAuthMethods {
		if strings.ToLower(string(allowed)) == m {
			return true
		}
	}
	return false
}

// IsActive returns true when the app row is usable for issuing tokens.
func (a *App) IsActive() bool {
	return a.Status == "active" && a.DeletedAt == nil
}

// EffectiveServiceCodes returns the list of permission-service codes this
// app inherits from. If ServiceCodes is empty, defaults to [app.code]
// (the common 1:1 case from docs/APP_REGISTRATION.md). The 'core' service
// is added unconditionally — every app's tokens carry auth-server's own
// permissions.
func (a *App) EffectiveServiceCodes() []string {
	out := make([]string, 0, len(a.ServiceCodes)+2)
	if len(a.ServiceCodes) == 0 {
		out = append(out, a.Code)
	} else {
		out = append(out, a.ServiceCodes...)
	}
	// 'core' is always implicit — auth-server's own permission slice.
	hasCore := false
	for _, s := range out {
		if s == "core" {
			hasCore = true
			break
		}
	}
	if !hasCore {
		out = append(out, "core")
	}
	return out
}

// WriteNamespaces returns the ordered, de-duplicated list of user
// pools new registrants created through this app are written to
// (migration 018). The FIRST entry is the user's home namespace
// (users.namespace); the rest become user_namespaces membership rows.
// Resolution: RegistrationNamespaces when non-empty → singular
// RegistrationNamespace (017 back-compat) → [DefaultNamespace].
func (a *App) WriteNamespaces() []string {
	out := []string{}
	seen := map[string]bool{}
	if a != nil {
		for _, ns := range a.RegistrationNamespaces {
			s := strings.TrimSpace(string(ns))
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
		if len(out) == 0 && a.RegistrationNamespace != nil {
			if s := strings.TrimSpace(*a.RegistrationNamespace); s != "" {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, DefaultNamespace)
	}
	return out
}

// WriteNamespace returns the PRIMARY write pool — the home namespace
// (users.namespace) for new registrants. First entry of
// WriteNamespaces(). See docs/USER_POOLS.md.
func (a *App) WriteNamespace() string {
	return a.WriteNamespaces()[0]
}

// EffectiveReadNamespaces returns the resolved set of user pools this
// app authenticates against. Always includes every write namespace and
// falls back to [DefaultNamespace] when nothing is configured.
// De-duplicated; write namespaces first so they win ties
// deterministically.
func (a *App) EffectiveReadNamespaces() []string {
	out := a.WriteNamespaces()
	seen := map[string]bool{}
	for _, ns := range out {
		seen[ns] = true
	}
	if a != nil {
		for _, ns := range a.ReadNamespaces {
			s := strings.TrimSpace(string(ns))
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// UserApp is a (user, app) membership row.
type UserApp struct {
	UserID    types.ID        `db:"user_id" json:"user_id"`
	AppID     types.ID        `db:"app_id" json:"app_id"`
	GrantedAt types.Timestamp `db:"granted_at" json:"granted_at"`
	GrantedBy *types.ID       `db:"granted_by" json:"granted_by,omitempty"`
	Status    string          `db:"status" json:"status"`
}

// IsActive reports whether this membership currently grants access.
func (u *UserApp) IsActive() bool { return u.Status == "active" }
