package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Administration of registered relying parties. Kept apart from the runtime store methods because these
// are operator actions with a very different risk profile — a bad write here silently breaks every login
// through that client, or worse, widens what it may read.

// ClientInput is a create/update payload. Pointers distinguish "not supplied" from "set to empty" on
// update; a nil field is left untouched rather than blanked, which is the difference between editing one
// field in a form and wiping the rest of the record.
type ClientInput struct {
	Name           *string
	Description    *string
	LogoURL        *string
	RedirectURIs   *[]string
	PostLogoutURIs *[]string
	AllowedScopes  *[]string
	GrantTypes     *[]string
	AppCode        *string
	Trusted        *bool
	RequirePKCE    *bool
	Status         *string
}

// ListClients returns every registered client, newest first.
func (s *Store) ListClients(ctx context.Context) ([]*Client, error) {
	var out []*Client
	err := s.db.SelectContext(ctx, &out, `
		SELECT client_id, client_secret_hash, name, description, logo_url, redirect_uris,
		       post_logout_uris, allowed_scopes, grant_types, app_code, trusted, require_pkce, status
		FROM oauth_clients ORDER BY created_at DESC`)
	return out, err
}

// GenerateSecret returns a new client secret and its hash. The PLAINTEXT is returned exactly once, to be
// shown to the operator and never stored — the same posture as the CivicGate API keys.
func GenerateSecret() (plain string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	plain = "cgs_" + base64.RawURLEncoding.EncodeToString(b)
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return plain, string(h), nil
}

// CreateClient registers a relying party. `public` omits the secret entirely — correct for a SPA or mobile
// app, which cannot keep one; PKCE is what protects those instead.
func (s *Store) CreateClient(ctx context.Context, clientID string, in ClientInput, public bool) (secret string, err error) {
	var hash, prefix any
	if !public {
		plain, h, gerr := GenerateSecret()
		if gerr != nil {
			return "", gerr
		}
		// The prefix is recorded here too (migration 028) so an admin-created client renders the same way
		// a self-service one does. Additive only — nothing reads it to make a decision.
		secret, hash, prefix = plain, h, SecretPrefix(plain)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oauth_clients (client_id, client_secret_hash, client_secret_prefix, name, description, logo_url,
			redirect_uris, post_logout_uris, allowed_scopes, grant_types, app_code, trusted, require_pkce, status)
		VALUES ($1,$2,$14,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,COALESCE($13,'active'))`,
		clientID, hash, deref(in.Name), deref(in.Description), deref(in.LogoURL),
		pq.StringArray(derefSlice(in.RedirectURIs)), pq.StringArray(derefSlice(in.PostLogoutURIs)),
		pq.StringArray(derefSlice(in.AllowedScopes)), pq.StringArray(derefSlice(in.GrantTypes)),
		nullIfEmpty(deref(in.AppCode)), derefBool(in.Trusted), derefBoolDefault(in.RequirePKCE, true),
		nullIfEmpty(deref(in.Status)), prefix)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// UpdateClient patches only the fields supplied.
func (s *Store) UpdateClient(ctx context.Context, clientID string, in ClientInput) error {
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
		add("logo_url", *in.LogoURL)
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
	if in.GrantTypes != nil {
		add("grant_types", pq.StringArray(*in.GrantTypes))
	}
	if in.AppCode != nil {
		add("app_code", nullIfEmpty(*in.AppCode))
	}
	if in.Trusted != nil {
		add("trusted", *in.Trusted)
	}
	if in.RequirePKCE != nil {
		add("require_pkce", *in.RequirePKCE)
	}
	if in.Status != nil {
		add("status", *in.Status)
	}
	if set == "" {
		return nil
	}
	args = append(args, clientID)
	_, err := s.db.ExecContext(ctx,
		fmt.Sprintf("UPDATE oauth_clients SET %s, updated_at = now() WHERE client_id = $%d", set, i), args...)
	return err
}

// RotateSecret issues a new secret. The old one stops working immediately — rotation is a revocation, and
// pretending otherwise would leave a leaked secret live.
func (s *Store) RotateSecret(ctx context.Context, clientID string) (string, error) {
	plain, hash, err := GenerateSecret()
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE oauth_clients SET client_secret_hash = $1, client_secret_prefix = $2, updated_at = now()
		  WHERE client_id = $3`, hash, SecretPrefix(plain), clientID)
	if err != nil {
		return "", err
	}
	return plain, nil
}

// DeleteClient removes a relying party and every code issued to it.
func (s *Store) DeleteClient(ctx context.Context, clientID string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_authorization_codes WHERE client_id = $1`, clientID); err != nil {
		return err
	}
	// Consents go too: leaving them would silently re-grant a future client that reused the id.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oauth_consents WHERE client_id = $1`, clientID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_clients WHERE client_id = $1`, clientID)
	return err
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func derefSlice(p *[]string) []string {
	// A non-nil POINTER to a NIL SLICE is the trap here: pq.StringArray(nil) marshals to SQL NULL, which
	// violates the NOT NULL on these columns. An omitted JSON field produces exactly that shape, so both
	// the nil pointer and the nil slice must collapse to an empty array.
	if p == nil || *p == nil {
		return []string{}
	}
	return *p
}
func derefBool(p *bool) bool { return p != nil && *p }
func derefBoolDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
