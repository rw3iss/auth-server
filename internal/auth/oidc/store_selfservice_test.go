package oidc

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
)

// THE OWNERSHIP FILTER IS THE OTHER THING THAT MUST NOT REGRESS.
//
// These tests assert it where it actually lives — in the SQL sent to the database — rather than in some
// Go-level `if` a caller might skip. The distinction is the whole point of the design: a "fetch, then
// compare, then act" implementation would pass a test that only checked the returned error, while still
// having a window between the check and the write and, more practically, a single `if` that a future
// edit can move or short-circuit. If the predicate is in the statement, then a statement without it is
// visibly wrong.
//
// Two layers of coverage, because they fail differently:
//   1. Per-method tests below assert the exact statement and its bound arguments.
//   2. TestEverySelfServiceStatementConstrainsTheOwner parses the source and catches a NEW method added
//      later without an owner clause — which no per-method test can, because nobody wrote one for it.

const (
	testOwner = "11111111-1111-1111-1111-111111111111"
	otherUser = "22222222-2222-2222-2222-222222222222"
)

func newMockStore(t *testing.T) (*Store, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectation: %v", err)
		}
		_ = db.Close()
	})
	return &Store{db: sqlx.NewDb(db, "postgres")}, mock
}

// clientRows builds a full projection row so sqlx can scan into Client.
func clientRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"client_id", "client_secret_hash", "name", "description", "logo_url", "redirect_uris",
		"post_logout_uris", "allowed_scopes", "grant_types", "app_code", "trusted", "require_pkce",
		"status", "owner_user_id", "client_secret_prefix", "created_at",
	})
}

func oneClientRow() *sqlmock.Rows {
	return clientRows().AddRow(
		"my-app-abc123", "$2a$10$hash", "My App", "desc", nil,
		[]byte(`{https://example.com/cb}`), []byte(`{}`), []byte(`{openid,profile,email}`),
		[]byte(`{authorization_code,refresh_token}`), nil, false, true,
		"active", testOwner, "cgs_AbCdEfGh", sql.NullTime{}.Time,
	)
}

// ── Reads ────────────────────────────────────────────────────────────────────────────────────────────

func TestListClientsByOwnerFiltersOnTheOwnerInTheQuery(t *testing.T) {
	store, mock := newMockStore(t)
	mock.ExpectQuery(`FROM oauth_clients\s+WHERE owner_user_id = \$1`).
		WithArgs(testOwner).
		WillReturnRows(oneClientRow())

	got, err := store.ListClientsByOwner(context.Background(), testOwner)
	if err != nil {
		t.Fatalf("ListClientsByOwner: %v", err)
	}
	if len(got) != 1 || got[0].ClientID != "my-app-abc123" {
		t.Fatalf("got %+v", got)
	}
}

func TestListClientsByOwnerReturnsEmptyNotNil(t *testing.T) {
	// The handler marshals this straight to JSON. A nil slice becomes `null`, which every client then has
	// to special-case; an empty list is the honest answer to "you have no applications".
	store, mock := newMockStore(t)
	mock.ExpectQuery(`FROM oauth_clients`).WithArgs(otherUser).WillReturnRows(clientRows())

	got, err := store.ListClientsByOwner(context.Background(), otherUser)
	if err != nil {
		t.Fatalf("ListClientsByOwner: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("got %#v, want an empty non-nil slice", got)
	}
}

func TestGetClientByOwnerBindsBothTheClientAndTheOwner(t *testing.T) {
	store, mock := newMockStore(t)
	mock.ExpectQuery(`WHERE client_id = \$1 AND owner_user_id = \$2`).
		WithArgs("my-app-abc123", testOwner).
		WillReturnRows(oneClientRow())

	if _, err := store.GetClientByOwner(context.Background(), "my-app-abc123", testOwner); err != nil {
		t.Fatalf("GetClientByOwner: %v", err)
	}
}

func TestGetClientByOwnerReportsNotFoundForSomebodyElsesClient(t *testing.T) {
	// The row exists; it is simply not this caller's, so the owner clause matches nothing. The answer is
	// ErrClientNotFound rather than a distinguishable "forbidden" — telling a caller that a client id
	// exists but is not theirs is an enumeration oracle over every registered application.
	store, mock := newMockStore(t)
	mock.ExpectQuery(`WHERE client_id = \$1 AND owner_user_id = \$2`).
		WithArgs("civicgate-web", otherUser).
		WillReturnRows(clientRows()) // no rows: the filter excluded it

	_, err := store.GetClientByOwner(context.Background(), "civicgate-web", otherUser)
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("err = %v, want ErrClientNotFound", err)
	}
}

// ── Writes ───────────────────────────────────────────────────────────────────────────────────────────

func TestUpdateClientByOwnerPutsTheOwnerInTheWhereClause(t *testing.T) {
	store, mock := newMockStore(t)
	name := "Renamed"
	redirects := []string{"https://example.com/cb"}
	mock.ExpectExec(`UPDATE oauth_clients SET .* WHERE client_id = \$\d+ AND owner_user_id = \$\d+`).
		WithArgs(name, sqlmock.AnyArg(), "my-app-abc123", testOwner).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := store.UpdateClientByOwner(context.Background(), "my-app-abc123", testOwner,
		ClientInput{Name: &name, RedirectURIs: &redirects})
	if err != nil {
		t.Fatalf("UpdateClientByOwner: %v", err)
	}
}

func TestUpdateClientByOwnerReportsNotFoundWhenNoRowMatched(t *testing.T) {
	// Zero rows affected is the ONLY signal that the owner clause excluded the row, so it must not be
	// mistaken for "nothing needed changing".
	store, mock := newMockStore(t)
	name := "Hijacked"
	mock.ExpectExec(`UPDATE oauth_clients`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := store.UpdateClientByOwner(context.Background(), "civicgate-web", otherUser, ClientInput{Name: &name})
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("err = %v, want ErrClientNotFound", err)
	}
}

func TestUpdateClientByOwnerWithNothingToChangeStillChecksOwnership(t *testing.T) {
	// An empty PATCH must not answer "updated" for a client the caller does not own — that alone would
	// confirm the client exists. With no SET clause to run, it falls back to the owner-filtered read.
	store, mock := newMockStore(t)
	mock.ExpectQuery(`WHERE client_id = \$1 AND owner_user_id = \$2`).
		WithArgs("civicgate-web", otherUser).
		WillReturnRows(clientRows())

	err := store.UpdateClientByOwner(context.Background(), "civicgate-web", otherUser, ClientInput{})
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("err = %v, want ErrClientNotFound", err)
	}
}

func TestUpdateClientByOwnerCannotWritePrivilegedColumns(t *testing.T) {
	// Even when the caller manages to populate them, `trusted` (skips the consent screen), `app_code`
	// (scopes the minted token to another application's namespace), `require_pkce` (the only thing
	// binding a code to its requester) and `grant_types` are absent from the SET clause by construction.
	store, mock := newMockStore(t)
	trusted := true
	pkce := false
	appCode := "civicgate"
	grants := []string{"client_credentials"}
	name := "Escalate"

	in := ClientInput{
		Name: &name, Trusted: &trusted, RequirePKCE: &pkce, AppCode: &appCode, GrantTypes: &grants,
	}

	// Only ONE bound argument beyond the two identifiers: the name. Had any of the privileged fields
	// reached the SET clause they would each have contributed a parameter, so the argument list is a
	// direct assertion on which columns the statement writes.
	mock.ExpectExec(`UPDATE oauth_clients SET name = \$1, updated_at = now\(\) WHERE client_id = \$2 AND owner_user_id = \$3`).
		WithArgs(name, "my-app-abc123", testOwner).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.UpdateClientByOwner(context.Background(), "my-app-abc123", testOwner, in); err != nil {
		t.Fatalf("UpdateClientByOwner: %v", err)
	}
}

func TestRotateSecretByOwnerFiltersOnTheOwnerAndStoresOnlyAHash(t *testing.T) {
	store, mock := newMockStore(t)

	// Capture what actually goes into the columns. The plaintext secret must never be one of them: the
	// whole one-time-secret posture collapses if a bcrypt hash is not what is stored.
	var storedHash, storedPrefix string
	mock.ExpectExec(`UPDATE oauth_clients\s+SET client_secret_hash = \$1, client_secret_prefix = \$2.*WHERE client_id = \$3 AND owner_user_id = \$4`).
		WithArgs(
			matchInto(&storedHash), matchInto(&storedPrefix), "my-app-abc123", testOwner,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	secret, err := store.RotateSecretByOwner(context.Background(), "my-app-abc123", testOwner)
	if err != nil {
		t.Fatalf("RotateSecretByOwner: %v", err)
	}
	if !strings.HasPrefix(secret, "cgs_") || len(secret) < 40 {
		t.Fatalf("secret %q does not look like a freshly minted client secret", secret)
	}
	if storedHash == secret {
		t.Fatal("the plaintext secret was written to client_secret_hash")
	}
	if !strings.HasPrefix(storedHash, "$2") {
		t.Fatalf("client_secret_hash = %q, want a bcrypt hash", storedHash)
	}
	if storedPrefix != secret[:12] || len(storedPrefix) >= len(secret) {
		t.Fatalf("client_secret_prefix = %q, want the first 12 characters of the secret and nothing more", storedPrefix)
	}
}

// matchInto is a sqlmock argument matcher that always matches and records what it saw, so a test can
// assert on a value the code generated internally.
type capture struct{ into *string }

func matchInto(dst *string) sqlmock.Argument { return capture{into: dst} }

func (c capture) Match(v driver.Value) bool {
	if s, ok := v.(string); ok {
		*c.into = s
	}
	return true
}

func TestRotateSecretByOwnerReportsNotFoundForSomebodyElsesClient(t *testing.T) {
	store, mock := newMockStore(t)
	mock.ExpectExec(`UPDATE oauth_clients`).WillReturnResult(sqlmock.NewResult(0, 0))

	_, err := store.RotateSecretByOwner(context.Background(), "civicgate-web", otherUser)
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("err = %v, want ErrClientNotFound", err)
	}
}

func TestDeleteClientByOwnerTouchesNothingWhenTheClientIsNotYours(t *testing.T) {
	// ORDER IS THE SAFETY PROPERTY HERE. The owner-filtered delete of the client row runs FIRST; if it
	// matches nothing the transaction rolls back and no authorization code or consent belonging to
	// somebody else's client was deleted. Deleting the children first — as the administrative path does,
	// where authorisation is already settled — would let a caller wipe another client's codes by naming
	// its id. sqlmock fails the test if either child DELETE is issued, because neither is expected.
	store, mock := newMockStore(t)
	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM oauth_clients WHERE client_id = \$1 AND owner_user_id = \$2`).
		WithArgs("civicgate-web", otherUser).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err := store.DeleteClientByOwner(context.Background(), "civicgate-web", otherUser)
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("err = %v, want ErrClientNotFound", err)
	}
}

func TestDeleteClientByOwnerRemovesCodesAndConsentsAfterTheOwnedRow(t *testing.T) {
	store, mock := newMockStore(t)
	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM oauth_clients WHERE client_id = \$1 AND owner_user_id = \$2`).
		WithArgs("my-app-abc123", testOwner).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM oauth_authorization_codes WHERE client_id = \$1`).
		WithArgs("my-app-abc123").WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`DELETE FROM oauth_consents WHERE client_id = \$1`).
		WithArgs("my-app-abc123").WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	if err := store.DeleteClientByOwner(context.Background(), "my-app-abc123", testOwner); err != nil {
		t.Fatalf("DeleteClientByOwner: %v", err)
	}
}

func TestCreateOwnedClientStampsTheOwnerAndForcesTheSafeDefaults(t *testing.T) {
	store, mock := newMockStore(t)
	name := "My App"
	redirects := []string{"https://example.com/cb"}
	scopes := []string{"openid", "profile"}
	grants := []string{"authorization_code", "refresh_token"}

	// FALSE for trusted, TRUE for require_pkce and NULL for app_code are literals in the statement, not
	// parameters — a self-service client cannot be given any of them regardless of what was posted.
	mock.ExpectExec(`INSERT INTO oauth_clients .*SELECT \$1,\$2,\$3,\$4,\$5,\$6,\$7,\$8,\$9,\$10,NULL,FALSE,TRUE,'active',\$11\s+WHERE \(SELECT count\(\*\) FROM oauth_clients WHERE owner_user_id = \$11\) < \$12`).
		WillReturnResult(sqlmock.NewResult(0, 1))

	secret, err := store.CreateOwnedClient(context.Background(), "my-app-abc123", ClientInput{
		Name: &name, RedirectURIs: &redirects, AllowedScopes: &scopes, GrantTypes: &grants,
	}, testOwner, false)
	if err != nil {
		t.Fatalf("CreateOwnedClient: %v", err)
	}
	if !strings.HasPrefix(secret, "cgs_") {
		t.Fatalf("secret %q does not look minted", secret)
	}
}

func TestCreateOwnedClientEnforcesTheCapInsideTheInsert(t *testing.T) {
	// The cap is a predicate on the INSERT, so no row lands when the account is already at the limit —
	// as opposed to a separate SELECT the caller could race past with a handful of parallel requests.
	store, mock := newMockStore(t)
	name := "One Too Many"
	redirects := []string{"https://example.com/cb"}
	mock.ExpectExec(`INSERT INTO oauth_clients`).WillReturnResult(sqlmock.NewResult(0, 0))

	_, err := store.CreateOwnedClient(context.Background(), "my-app-abc123", ClientInput{
		Name: &name, RedirectURIs: &redirects,
	}, testOwner, true)
	if !errors.Is(err, ErrClientLimitReached) {
		t.Fatalf("err = %v, want ErrClientLimitReached", err)
	}
}

func TestCreateOwnedClientPublicClientsGetNoSecret(t *testing.T) {
	store, mock := newMockStore(t)
	name := "SPA"
	redirects := []string{"https://example.com/cb"}
	mock.ExpectExec(`INSERT INTO oauth_clients`).WillReturnResult(sqlmock.NewResult(0, 1))

	secret, err := store.CreateOwnedClient(context.Background(), "spa-abc", ClientInput{
		Name: &name, RedirectURIs: &redirects,
	}, testOwner, true)
	if err != nil {
		t.Fatalf("CreateOwnedClient: %v", err)
	}
	if secret != "" {
		t.Fatalf("a public client must get no secret, got %q — PKCE is what protects it", secret)
	}
}

// ── The invariant, checked against the source itself ─────────────────────────────────────────────────

// TestEverySelfServiceStatementConstrainsTheOwner parses store_selfservice.go and requires that every SQL
// literal touching `oauth_clients` also constrains `owner_user_id`.
//
// This is the test that covers the method NOBODY HAS WRITTEN YET. The per-method tests above only prove
// the statements that exist today; the one realistic way this surface becomes a vulnerability is somebody
// adding a seventh self-service query later and forgetting the clause, and no existing test would notice.
//
// The child DELETEs on oauth_authorization_codes / oauth_consents are exempt by name: they are reached
// only after the owner-filtered delete of the parent row matched, which the ordering test above pins.
func TestEverySelfServiceStatementConstrainsTheOwner(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "store_selfservice.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	checked := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		sqlText, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		lower := strings.ToLower(sqlText)
		if !strings.Contains(lower, "oauth_clients") {
			return true
		}
		checked++
		if !strings.Contains(lower, "owner_user_id") {
			t.Errorf("a statement touching oauth_clients does not mention owner_user_id:\n%s\n\n"+
				"Every self-service read and write must carry the owner in its WHERE clause. "+
				"If this statement genuinely does not need it, it does not belong in this file.",
				strings.TrimSpace(sqlText))
		}
		return true
	})

	if checked < 5 {
		// A guard on the guard: if a refactor moves the SQL out of literals (into a builder, a constant in
		// another file, a query package) this test silently starts passing while checking nothing.
		t.Fatalf("only %d oauth_clients statements found in store_selfservice.go — the source scan is no longer seeing the queries it is meant to check", checked)
	}
}
