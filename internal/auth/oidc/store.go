package oidc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Store is the OIDC provider's persistence: registered clients, authorization codes, standing consents.
type Store struct{ db *sqlx.DB }

func NewStore(db *sqlx.DB) *Store { return &Store{db: db} }

// Client is a registered relying party.
type Client struct {
	ClientID         string         `db:"client_id"`
	ClientSecretHash sql.NullString `db:"client_secret_hash"`
	Name             string         `db:"name"`
	Description      sql.NullString `db:"description"`
	LogoURL          sql.NullString `db:"logo_url"`
	RedirectURIs     pq.StringArray `db:"redirect_uris"`
	PostLogoutURIs   pq.StringArray `db:"post_logout_uris"`
	AllowedScopes    pq.StringArray `db:"allowed_scopes"`
	GrantTypes       pq.StringArray `db:"grant_types"`
	AppCode          sql.NullString `db:"app_code"`
	Trusted          bool           `db:"trusted"`
	RequirePKCE      bool           `db:"require_pkce"`
	Status           string         `db:"status"`

	// Self-service registration (migration 028). OwnerUserID is NULL for an administrator-created client,
	// which is what keeps those rows invisible to the owner-filtered queries — `owner_user_id = $caller`
	// simply never matches NULL. SecretPrefix is the first few characters of the secret, so a UI can name
	// which secret is live without being able to reproduce it.
	OwnerUserID  sql.NullString `db:"owner_user_id"`
	SecretPrefix sql.NullString `db:"client_secret_prefix"`
	CreatedAt    time.Time      `db:"created_at"`
}

// IsPublic reports a client with no secret — a SPA or mobile app. Public clients cannot authenticate
// themselves at the token endpoint, so PKCE is the only thing binding a code to its requester.
func (c *Client) IsPublic() bool { return !c.ClientSecretHash.Valid || c.ClientSecretHash.String == "" }

// AllowsRedirect does an EXACT match against the registered list.
//
// Exact, never prefix or wildcard: a prefix match on "https://app.example.com/cb" also accepts
// "https://app.example.com/cb.attacker.net", which hands the authorization code — and the user's session —
// to whoever registered that host. This one comparison is the difference between a safe IdP and a
// credential-forwarding service.
func (c *Client) AllowsRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// AllowsOrigin reports whether `origin` (a bare scheme://host[:port], as sent in
// the Origin header) belongs to this client.
//
// FedCM has no redirect_uri — the browser hands the token straight to the calling
// page — so the Origin header is the only thing identifying who is asking, and it
// has to be checked against something the client already proved it controls. That
// something is the registered redirect_uris and post_logout_uris: their origins are
// exactly the set of places this client was authorised to receive a session at.
//
// DERIVED, NOT A SECOND ALLOW-LIST. A separate fedcm_origins column would be a
// second place to get this right, and the two would eventually disagree — the same
// reason FedCM reuses oauth_clients rather than introducing a client registry of
// its own. A FedCM-only relying party registers its origin as a redirect_uri, which
// is a field every OIDC client already fills in.
func (c *Client) AllowsOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	want := normalizeOrigin(origin)
	if want == "" {
		return false
	}
	for _, u := range append(append([]string{}, c.RedirectURIs...), c.PostLogoutURIs...) {
		if normalizeOrigin(u) == want {
			return true
		}
	}
	return false
}

// PrimaryOrigin returns the origin of the client's first registered redirect URI,
// or "" when it has none. Used for links we can only derive rather than store.
func (c *Client) PrimaryOrigin() string {
	for _, u := range c.RedirectURIs {
		if o := normalizeOrigin(u); o != "" {
			return o
		}
	}
	return ""
}

// normalizeOrigin reduces a URL to scheme://host[:port], lowercased.
//
// The default port is dropped because a browser's Origin header never carries one
// ("https://x.example", not "https://x.example:443") while a registered redirect
// URI reasonably might — and a comparison that treats those as different rejects a
// legitimate relying party for a reason nothing in the response would explain.
func normalizeOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + host + ":" + port
	}
	return scheme + "://" + host
}

// AllowsScope reports whether the client is permitted to request a scope at all.
func (c *Client) AllowsScope(scope string) bool {
	for _, s := range c.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// FilterScopes intersects a request with what the client may ever ask for, so a compromised client cannot
// escalate its own access by simply asking for more.
func (c *Client) FilterScopes(requested []string) []string {
	out := []string{}
	for _, s := range requested {
		if c.AllowsScope(s) {
			out = append(out, s)
		}
	}
	return out
}

var ErrClientNotFound = errors.New("client not found")

func (s *Store) GetClient(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	err := s.db.GetContext(ctx, &c, `
		SELECT client_id, client_secret_hash, name, description, logo_url, redirect_uris,
		       post_logout_uris, allowed_scopes, grant_types, app_code, trusted, require_pkce, status
		FROM oauth_clients WHERE client_id = $1 AND status = 'active'`, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return &c, nil
}

// hashCode stores authorization codes hashed, for the same reason passwords are: a database read must not
// yield anything directly replayable.
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// AuthCode is a stored authorization code.
type AuthCode struct {
	ClientID            string         `db:"client_id"`
	UserID              string         `db:"user_id"`
	RedirectURI         string         `db:"redirect_uri"`
	Scopes              pq.StringArray `db:"scopes"`
	Nonce               sql.NullString `db:"nonce"`
	CodeChallenge       sql.NullString `db:"code_challenge"`
	CodeChallengeMethod sql.NullString `db:"code_challenge_method"`
	AuthTime            time.Time      `db:"auth_time"`
	ExpiresAt           time.Time      `db:"expires_at"`
	ConsumedAt          sql.NullTime   `db:"consumed_at"`
}

func (s *Store) SaveAuthCode(ctx context.Context, code string, c AuthCode) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_authorization_codes
			(code, client_id, user_id, redirect_uri, scopes, nonce, code_challenge, code_challenge_method, auth_time, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		hashCode(code), c.ClientID, c.UserID, c.RedirectURI, c.Scopes,
		c.Nonce, c.CodeChallenge, c.CodeChallengeMethod, c.AuthTime, c.ExpiresAt)
	return err
}

var (
	ErrCodeNotFound = errors.New("authorization code not found")
	ErrCodeReplayed = errors.New("authorization code already used")
	ErrCodeExpired  = errors.New("authorization code expired")
)

// ConsumeAuthCode atomically marks a code used and returns it.
//
// The UPDATE ... WHERE consumed_at IS NULL ... RETURNING is what makes redemption single-use under
// concurrency: two simultaneous redemptions cannot both win, because only one UPDATE can match. Checking
// then updating would leave a window where both succeed.
func (s *Store) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	var c AuthCode
	err := s.db.GetContext(ctx, &c, `
		UPDATE oauth_authorization_codes
		   SET consumed_at = now()
		 WHERE code = $1 AND consumed_at IS NULL
		RETURNING client_id, user_id, redirect_uri, scopes, nonce,
		          code_challenge, code_challenge_method, auth_time, expires_at, consumed_at`,
		hashCode(code))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Either it never existed or it was already redeemed. A replayed code is a sign of
			// interception, so the caller treats both the same and reveals neither.
			return nil, ErrCodeNotFound
		}
		return nil, err
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, ErrCodeExpired
	}
	return &c, nil
}

// VerifyPKCE checks a code_verifier against the stored challenge (RFC 7636).
func VerifyPKCE(challenge, method, verifier string) bool {
	if challenge == "" {
		return true // no challenge was recorded; the caller decides whether that was allowed
	}
	if verifier == "" {
		return false
	}
	switch method {
	case "S256", "":
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
	case "plain":
		// Accepted only because the RFC defines it; the authorize handler refuses to record it.
		return verifier == challenge
	default:
		return false
	}
}

// GetConsent returns the scopes a user has already granted a client.
func (s *Store) GetConsent(ctx context.Context, userID, clientID string) ([]string, error) {
	var scopes pq.StringArray
	err := s.db.GetContext(ctx, &scopes,
		`SELECT scopes FROM oauth_consents WHERE user_id = $1 AND client_id = $2`, userID, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return scopes, nil
}

// SaveConsent records (or widens) a standing grant.
func (s *Store) SaveConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_consents (user_id, client_id, scopes) VALUES ($1,$2,$3)
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = $3, updated_at = now()`,
		userID, clientID, pq.StringArray(scopes))
	return err
}

// ListConsentedClients returns every client this user has a standing grant with.
//
// FedCM's accounts endpoint reports these as `approved_clients`, which is what
// tells the browser whether to show the "you are about to share…" disclosure. It
// reads the same oauth_consents rows the OIDC consent screen writes, so a grant
// made through either flow is honoured by both — and revoking it once revokes it
// for both.
func (s *Store) ListConsentedClients(ctx context.Context, userID string) ([]string, error) {
	var ids []string
	err := s.db.SelectContext(ctx, &ids,
		`SELECT client_id FROM oauth_consents WHERE user_id = $1 ORDER BY client_id`, userID)
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// DeleteConsent removes a standing grant. Used by FedCM's disconnect endpoint and
// by any "revoke this app" UI.
//
// Deleting a row that is not there is success, not an error: disconnect is
// idempotent by nature, and a relying party retrying it must not get a failure for
// having already succeeded.
func (s *Store) DeleteConsent(ctx context.Context, userID, clientID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_consents WHERE user_id = $1 AND client_id = $2`, userID, clientID)
	return err
}

// PurgeExpiredCodes removes spent/expired codes. Called by the background job sweep.
func (s *Store) PurgeExpiredCodes(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_authorization_codes WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
