package domain

import (
	"time"

	"github.com/lib/pq"

	"github.com/ven/auth/pkg/shared/models"
	"github.com/ven/auth/pkg/shared/types"
)

// M2MClient is a registered OAuth2 client_credentials consumer — a
// service / cron / batch job / CI runner that can mint short-lived
// service-principal access tokens via POST /oauth/token.
//
// Closes the AUTH_REGISTRATION_TOKEN shim noted in auth-server-client's
// README: rotatable, revocable, scope-limited credentials in place of a
// long-lived pre-issued JWT.
//
// Lifecycle:
//   - Created by system_admin via POST /admin/m2m-clients. The plaintext
//     secret is returned ONCE in the response — never recoverable. To
//     recover from a lost secret, rotate the client (delete + recreate
//     or add a rotate endpoint).
//   - Used: consumer POSTs { grant_type, client_id, client_secret } to
//     /oauth/token. On success the server stamps LastUsedAt and returns
//     a service-principal access token.
//   - Revoked: soft-delete via RevokedAt. The hot-path lookup index
//     filters revoked rows so the grant fails identically to "wrong
//     credentials" — same error envelope, no leak.
//
// Storage:
//   - ClientID is operator-chosen and globally unique (UNIQUE constraint
//     on the column). Operator picks something readable: "rm-prod",
//     "ci-runner-eu-1", etc.
//   - ClientSecretHash is bcrypt at server's configured BCRYPT_COST.
//   - Scopes / AllowedAudiences are pq.StringArray (TEXT[] in Postgres).
type M2MClient struct {
	models.BaseModel

	// ClientID is the operator-chosen unique identifier shown to consumers.
	// Indexed for hot-path /oauth/token lookup.
	ClientID string `db:"client_id" json:"client_id"`

	// ClientSecretHash is the bcrypt-hashed secret. Plaintext is only
	// visible in the CreateClient response and is never persisted.
	ClientSecretHash string `db:"client_secret_hash" json:"-"`

	// Name is a human-readable label for dashboards and audit logs.
	Name string `db:"name" json:"name"`

	// Description optionally documents what this client is used for.
	Description string `db:"description" json:"description"`

	// Scopes is the permission catalog this client may assert. The
	// issued token's `scopes` claim is the intersection of Scopes and
	// any `scope` parameter on the grant request. Empty means "all
	// scopes the client owns" — equivalent to listing every Scopes
	// entry on each grant.
	Scopes pq.StringArray `db:"scopes" json:"scopes"`

	// AllowedAudiences optionally restricts which audiences the issued
	// tokens may target. Empty means the server's default audience
	// (`JWT_AUDIENCE`).
	AllowedAudiences pq.StringArray `db:"allowed_audiences" json:"allowed_audiences"`

	// Status is one of 'active' | 'disabled'. Disabled clients fail
	// the grant with the same error envelope as a wrong secret so the
	// distinction never leaks to the caller.
	Status string `db:"status" json:"status"`

	// LastUsedAt is stamped on every successful grant. Useful for
	// hygiene: "what's still consuming this credential before I revoke
	// it?". Nullable — never-used clients return nil.
	LastUsedAt *time.Time `db:"last_used_at" json:"last_used_at,omitempty"`

	// RevokedAt is the soft-revoke marker. The hot-path index filters
	// out non-nil values so revoked clients are invisible to the grant
	// flow.
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`

	// CreatedBy is the admin user that created this client. Optional
	// (NULL on cleanup if the user is hard-deleted — FK uses SET NULL).
	CreatedBy *types.ID `db:"created_by" json:"created_by,omitempty"`
}

// IsActive reports whether the client may currently mint tokens.
// Combines status, revoked state, and the soft-delete check from
// BaseModel. Used both pre-flight in the grant handler and as a
// belt-and-suspenders gate at issuance time.
func (m *M2MClient) IsActive() bool {
	return m.Status == "active" && m.RevokedAt == nil
}

// EffectiveScopes returns the scopes to stamp on a token, given an
// optional requested-scope slice from the grant request.
//
//   - requested empty → all configured Scopes are granted (full grant).
//   - requested non-empty → the intersection with Scopes (the client
//     cannot escalate beyond its catalog; unknown / out-of-bounds
//     entries are silently dropped, matching RFC 6749 §3.3).
//
// Empty result is valid and produces a token with no scopes — useful
// for clients that should authenticate but not be granted any specific
// permission (rare; an explicit "no-scope" client is sometimes used to
// prove identity in zero-trust pipelines).
func (m *M2MClient) EffectiveScopes(requested []string) []string {
	if len(requested) == 0 {
		out := make([]string, len(m.Scopes))
		copy(out, m.Scopes)
		return out
	}
	allowed := make(map[string]struct{}, len(m.Scopes))
	for _, s := range m.Scopes {
		allowed[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := allowed[s]; ok {
			out = append(out, s)
		}
	}
	return out
}
