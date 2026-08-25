package oidc

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lib/pq"
)

// Self-service relying-party registration: a developer registers their own application and manages it
// themselves, the way Google and GitHub let any account register an OAuth app.
//
// ═══ OWNERSHIP IS ENFORCED IN THE QUERY, NEVER AFTER IT ═══════════════════════════════════════════════
//
// Every function below carries `owner_user_id = $owner` inside the WHERE clause of the statement that
// actually reads or writes the row. There is deliberately no "fetch, compare, then act" anywhere in this
// file, because that shape has a window: between the check and the write the row can change hands, and
// more practically, the check is one `if` a future edit can move, forget or short-circuit. Putting the
// predicate in the statement makes the wrong thing impossible to express — a query that forgets the owner
// clause returns the wrong rows so obviously that it cannot survive a test.
//
// Administrator-created clients have a NULL owner. `owner_user_id = $owner` never matches NULL, so the
// first-party `civicgate-web` client — trusted, consent-skipping, holder of every civic:* scope — is
// invisible and untouchable through this surface without any special-casing at all. That is the property
// worth preserving in any future edit here: do not "helpfully" add `OR owner_user_id IS NULL`.
//
// Every miss returns ErrClientNotFound, whether the client does not exist or simply is not the caller's.
// Distinguishing the two would turn this into an oracle for which client ids are registered.

// SelfServiceScopes is the complete set a self-registered client may request.
//
// Identity only. A self-service registration cannot grant itself the civic:* scopes (location, interests,
// declared political positions, activity) — those read data a member has not agreed to hand to a stranger,
// and are granted by an administrator after a human decision. `offline_access` is excluded for a related
// reason: a refresh token is standing, long-lived access, which is not something a registration form
// should be able to award itself.
var SelfServiceScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail}

// MaxClientsPerOwner caps one account's registrations. Generous for anyone building something real,
// small enough that registration is useless as a way to flood the table.
const MaxClientsPerOwner = 10

// ErrClientLimitReached is returned when an account already holds MaxClientsPerOwner clients.
var ErrClientLimitReached = errors.New("client limit reached")

// selfServiceColumns is the projection every self-service read uses.
const selfServiceColumns = `client_id, client_secret_hash, name, description, logo_url, redirect_uris,
	post_logout_uris, allowed_scopes, grant_types, app_code, trusted, require_pkce, status,
	owner_user_id, client_secret_prefix, created_at`

// ListClientsByOwner returns the caller's own clients, newest first.
func (s *Store) ListClientsByOwner(ctx context.Context, ownerID string) ([]*Client, error) {
	var out []*Client
	err := s.db.SelectContext(ctx, &out, `
		SELECT `+selfServiceColumns+`
		FROM oauth_clients
		WHERE owner_user_id = $1
		ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []*Client{}
	}
	return out, nil
}

// GetClientByOwner returns one client, but only if it belongs to this owner.
//
// Note the absence of `AND status = 'active'` that GetClient carries: the runtime lookup must refuse a
// disabled client, but its owner still needs to see and manage it — otherwise disabling a client would
// make it disappear from the very screen that could re-enable it.
func (s *Store) GetClientByOwner(ctx context.Context, clientID, ownerID string) (*Client, error) {
	var c Client
	err := s.db.GetContext(ctx, &c, `
		SELECT `+selfServiceColumns+`
		FROM oauth_clients
		WHERE client_id = $1 AND owner_user_id = $2`, clientID, ownerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return &c, nil
}

// CountClientsByOwner reports how many clients an account holds.
func (s *Store) CountClientsByOwner(ctx context.Context, ownerID string) (int, error) {
	var n int
	err := s.db.GetContext(ctx, &n,
		`SELECT count(*) FROM oauth_clients WHERE owner_user_id = $1`, ownerID)
	return n, err
}

// CreateOwnedClient registers a client owned by `ownerID` and returns the secret, in the clear, exactly
// once. There is no endpoint that returns it again; the column holds a bcrypt hash.
//
// THE CAP IS PART OF THE WRITE. `INSERT … SELECT … WHERE (count) < cap` means the limit is evaluated by
// the same statement that inserts, rather than by a separate SELECT the caller could race past with a
// handful of parallel requests. Under READ COMMITTED two simultaneous inserts can still both observe
// cap-1 and both land, so this is a flood control rather than an invariant — which is the correct
// strength for it; the per-account create rate limit in the handler is the other half.
func (s *Store) CreateOwnedClient(ctx context.Context, clientID string, in ClientInput, ownerID string, public bool) (secret string, err error) {
	var hash, prefix any
	if !public {
		plain, h, gerr := GenerateSecret()
		if gerr != nil {
			return "", gerr
		}
		secret, hash, prefix = plain, h, SecretPrefix(plain)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_clients (client_id, client_secret_hash, client_secret_prefix, name, description,
			logo_url, redirect_uris, post_logout_uris, allowed_scopes, grant_types, app_code,
			trusted, require_pkce, status, owner_user_id)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,FALSE,TRUE,'active',$11
		WHERE (SELECT count(*) FROM oauth_clients WHERE owner_user_id = $11) < $12`,
		clientID, hash, prefix, deref(in.Name), deref(in.Description), deref(in.LogoURL),
		pq.StringArray(derefSlice(in.RedirectURIs)), pq.StringArray(derefSlice(in.PostLogoutURIs)),
		pq.StringArray(derefSlice(in.AllowedScopes)), pq.StringArray(derefSlice(in.GrantTypes)),
		ownerID, MaxClientsPerOwner)
	if err != nil {
		return "", err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if n == 0 {
		// The only way the INSERT matches no row is the cap predicate — a duplicate client_id would have
		// raised a unique violation above instead.
		return "", ErrClientLimitReached
	}
	return secret, nil
}

// UpdateClientByOwner patches only the supplied fields, and only on a row this owner holds.
//
// app_code, trusted and require_pkce are NOT settable here and are absent from the SET clause by
// construction rather than by filtering the input: app_code decides which app/namespace the minted token
// is scoped to, `trusted` skips the consent screen entirely, and turning off require_pkce removes the
// only thing binding an authorization code to the client that requested it. All three are administrative.
func (s *Store) UpdateClientByOwner(ctx context.Context, clientID, ownerID string, in ClientInput) error {
	set := ""
	args := []any{}
	i := 1
	add := func(col string, val any) {
		if set != "" {
			set += ", "
		}
		set += fmt.Sprintf("%s = $%d", col, i)
		args = append(args, val)
		i++
	}
	if in.Name != nil {
		add("name", *in.Name)
	}
	if in.Description != nil {
		add("description", *in.Description)
	}
	if in.LogoURL != nil {
		add("logo_url", nullIfEmpty(*in.LogoURL))
	}
	if in.RedirectURIs != nil {
		add("redirect_uris", pq.StringArray(*in.RedirectURIs))
	}
	if in.PostLogoutURIs != nil {
		add("post_logout_uris", pq.StringArray(*in.PostLogoutURIs))
	}
	if in.AllowedScopes != nil {
		add("allowed_scopes", pq.StringArray(*in.AllowedScopes))
	}
	if in.Status != nil {
		add("status", *in.Status)
	}
	if set == "" {
		// Nothing to change, but still confirm the client is theirs — otherwise an empty PATCH would
		// answer "updated" for a client the caller does not own, which is an existence oracle.
		_, err := s.GetClientByOwner(ctx, clientID, ownerID)
		return err
	}

	args = append(args, clientID, ownerID)
	res, err := s.db.ExecContext(ctx, fmt.Sprintf(
		`UPDATE oauth_clients SET %s, updated_at = now() WHERE client_id = $%d AND owner_user_id = $%d`,
		set, i, i+1), args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrClientNotFound
	}
	return nil
}

// RotateSecretByOwner issues a new secret for a client this owner holds. The previous secret stops
// working the instant this returns — rotation IS revocation, and pretending otherwise would leave a
// leaked secret live for however long the owner took to notice.
func (s *Store) RotateSecretByOwner(ctx context.Context, clientID, ownerID string) (string, error) {
	plain, hash, err := GenerateSecret()
	if err != nil {
		return "", err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE oauth_clients
		   SET client_secret_hash = $1, client_secret_prefix = $2, updated_at = now()
		 WHERE client_id = $3 AND owner_user_id = $4`,
		hash, SecretPrefix(plain), clientID, ownerID)
	if err != nil {
		return "", err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", ErrClientNotFound
	}
	return plain, nil
}

// DeleteClientByOwner removes a client this owner holds, plus every code and consent issued to it.
//
// ORDER MATTERS. The owner-filtered delete of the client row runs FIRST, inside a transaction: if it
// matches nothing the transaction rolls back and no code or consent belonging to somebody else's client
// was touched. Deleting the children first — as the administrative path does, where authorisation is
// already settled — would let a caller wipe another client's authorization codes by naming its id.
func (s *Store) DeleteClientByOwner(ctx context.Context, clientID, ownerID string) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`DELETE FROM oauth_clients WHERE client_id = $1 AND owner_user_id = $2`, clientID, ownerID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrClientNotFound
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM oauth_authorization_codes WHERE client_id = $1`, clientID); err != nil {
		return err
	}
	// Consents go too: leaving them would silently re-grant a future client that reused the id.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM oauth_consents WHERE client_id = $1`, clientID); err != nil {
		return err
	}
	return tx.Commit()
}

// ── Client ids and secret prefixes ───────────────────────────────────────────────────────────────────

// SecretPrefix is the leading, displayable slice of a client secret.
//
// The secret is "cgs_" plus 32 random bytes (256 bits) in base64; revealing eight of those characters
// leaves roughly 208 bits, so this identifies WHICH secret is live without meaningfully helping anyone
// guess it. Same posture as the CivicGate API keys: hash in the column, prefix for the UI, plaintext
// exactly once in the create/rotate response.
func SecretPrefix(plain string) string {
	if len(plain) <= 12 {
		return plain
	}
	return plain[:12]
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// MintClientID derives a public client id from the application's name plus random suffix.
//
// THE SERVER MINTS IT; the registrant does not choose it. A caller-chosen id is a squatting and
// impersonation surface — "civicgate-official", or simply grabbing an id an internal client was going to
// want — and the id is not a secret, so there is nothing gained by letting them pick. The name-derived
// prefix is purely so a developer can recognise their own client in a list of URLs.
func MintClientID(name string) (string, error) {
	slug := nonSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 24 {
		slug = strings.Trim(slug[:24], "-")
	}
	if slug == "" {
		slug = "app"
	}
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return slug + "-" + hex.EncodeToString(b), nil
}
