// Bulk pre-hashed user import (§4 of the GlobalSKU integration spec). Loads
// existing users WITH their existing password hashes so a one-shot cutover
// keeps everyone's current password working — no reset, no user-visible
// change. App-agnostic: the hash format is decoupled from core via the
// password.Registry, and the write pool + namespace tags follow the
// home=default + tags convention (docs/USER_POOLS.md).
package auth

import (
	"context"
	"strings"

	"github.com/ven/auth/internal/audit"
	"github.com/ven/auth/internal/auth/password"
	"github.com/ven/auth/internal/domain"
	"github.com/ven/auth/pkg/shared/errors"
	"github.com/ven/auth/pkg/shared/models"
	"github.com/ven/auth/pkg/shared/types"
	"github.com/ven/auth/pkg/shared/utils"
)

// MaxBulkImportRows caps a single request. Documented + enforced so a caller
// can't push an unbounded batch through one transaction-less loop.
const MaxBulkImportRows = 500

// BulkImportRow is one user to import with their pre-hashed credential.
type BulkImportRow struct {
	Email         string            `json:"email"`
	PasswordHash  string            `json:"password_hash"`
	HashAlgo      string            `json:"hash_algo,omitempty"` // default "bcrypt"
	FirstName     string            `json:"first_name,omitempty"`
	LastName      string            `json:"last_name,omitempty"`
	NamespaceTags []string          `json:"namespace_tags,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// BulkImportInput is the request envelope.
type BulkImportInput struct {
	// AppCode resolves the write namespace + tag set. Optional — when empty,
	// DefaultNamespace (or DefaultNamespaceOverride) is used.
	AppCode string `json:"app_code,omitempty"`
	// DefaultNamespace overrides the home pool when no AppCode is given.
	DefaultNamespace string          `json:"default_namespace,omitempty"`
	Users            []BulkImportRow `json:"users"`
	// Update, when true, refreshes an existing row's hash/name instead of
	// skipping it. Default false = idempotent no-clobber.
	Update bool `json:"update,omitempty"`
}

// BulkImportRowResult reports per-row outcome + the resulting uid so the
// caller can backfill its own foreign key (e.g. GlobalSKU users.ven_user_id).
type BulkImportRowResult struct {
	Email  string `json:"email"`
	Status string `json:"status"` // created | updated | skipped | error
	UID    string `json:"uid,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// BulkImportResult is the response envelope.
type BulkImportResult struct {
	Created int                   `json:"created"`
	Updated int                   `json:"updated"`
	Skipped int                   `json:"skipped"`
	Errored int                   `json:"errored"`
	Rows    []BulkImportRowResult `json:"rows"`
}

// BulkImport imports users with pre-hashed passwords (system_admin only — the
// route gate enforces that). Stores hashes verbatim; bcrypt verifies on the
// normal login path immediately. Idempotent upsert keyed by (namespace, email).
func (s *AuthService) BulkImport(ctx context.Context, in BulkImportInput) (*BulkImportResult, error) {
	if len(in.Users) == 0 {
		return nil, errors.InvalidInput("users", "at least one user is required")
	}
	if len(in.Users) > MaxBulkImportRows {
		return nil, errors.InvalidInput("users", "batch exceeds the maximum of 500 rows per request")
	}

	reg := s.hashers
	if reg == nil {
		reg = password.NewRegistry()
	}

	// Resolve the write pool (home namespace) + the tag set.
	writeNamespace := domain.DefaultNamespace
	if ns := strings.TrimSpace(in.DefaultNamespace); ns != "" {
		writeNamespace = strings.ToLower(ns)
	}
	var appTags []string
	var resolvedApp *domain.App
	if in.AppCode != "" && s.appService != nil {
		app, err := s.appService.GetByCode(ctx, in.AppCode)
		if err != nil || app == nil {
			return nil, errors.NotFound("app")
		}
		resolvedApp = app
		writeNamespace = app.WriteNamespace()
		appTags = domain.ExcludeHomeNamespace(app.EffectiveReadNamespaces(), writeNamespace)
	}

	baseRole, _ := s.roleRepo.GetByCode(ctx, string(models.RoleBaseUser))

	result := &BulkImportResult{Rows: make([]BulkImportRowResult, 0, len(in.Users))}
	for _, row := range in.Users {
		rr := s.importOne(ctx, row, in.Update, writeNamespace, appTags, baseRole, reg, resolvedApp)
		switch rr.Status {
		case "created":
			result.Created++
		case "updated":
			result.Updated++
		case "skipped":
			result.Skipped++
		default:
			result.Errored++
		}
		result.Rows = append(result.Rows, rr)
	}

	audit.Record(ctx, audit.Event{
		Action: "user.bulk_imported",
		Details: map[string]any{
			"app_code":  in.AppCode,
			"namespace": writeNamespace,
			"total":     len(in.Users),
			"created":   result.Created,
			"updated":   result.Updated,
			"skipped":   result.Skipped,
			"errored":   result.Errored,
		},
	})
	return result, nil
}

// importOne handles a single row. Errors are returned as a row status rather
// than aborting the batch — one malformed hash shouldn't sink 499 good rows.
func (s *AuthService) importOne(
	ctx context.Context,
	row BulkImportRow,
	update bool,
	writeNamespace string,
	appTags []string,
	baseRole *domain.Role,
	reg *password.Registry,
	app *domain.App,
) BulkImportRowResult {
	email := types.Email(utils.NormalizeEmail(row.Email))
	out := BulkImportRowResult{Email: string(email)}

	if !utils.IsValidEmail(string(email)) {
		out.Status, out.Reason = "error", "invalid email"
		return out
	}

	strategy, ok := reg.Get(row.HashAlgo)
	if !ok {
		out.Status, out.Reason = "error", "unsupported hash_algo: "+row.HashAlgo
		return out
	}
	storedHash, err := strategy.Validate(row.PasswordHash)
	if err != nil {
		out.Status, out.Reason = "error", err.Error()
		return out
	}

	// Idempotency: keyed by (namespace, email). Match within the write pool
	// (home or tag) so a re-run doesn't clobber a live credential.
	existing, lookupErr := s.userRepo.GetByEmailInNamespaces(ctx, email, []string{writeNamespace})
	if lookupErr == nil && existing != nil {
		if !update {
			out.Status, out.UID = "skipped", existing.ID.String()
			return out
		}
		existing.PasswordHash = storedHash
		if row.FirstName != "" {
			existing.FirstName = row.FirstName
		}
		if row.LastName != "" {
			existing.LastName = row.LastName
		}
		if err := s.userRepo.Update(ctx, existing); err != nil {
			out.Status, out.Reason = "error", "update failed"
			return out
		}
		s.applyImportTags(ctx, existing.ID, existing.Namespace, row.NamespaceTags, appTags)
		// Grant app + linked-app memberships + default-org role so an imported
		// user can actually log in to the app (idempotent; mirrors register /
		// login / JIT migration). Best-effort.
		if app != nil {
			s.ensureAppEntitlements(ctx, existing, app, EntitlementOverrides{})
		}
		out.Status, out.UID = "updated", existing.ID.String()
		return out
	}

	// Create a new user in the write pool with the hash stored verbatim.
	user := domain.NewUser(email, row.FirstName, row.LastName)
	user.Namespace = writeNamespace
	user.PasswordHash = storedHash
	user.Status = types.UserStatusActive
	if err := s.userRepo.Create(ctx, user); err != nil {
		out.Status, out.Reason = "error", "create failed"
		return out
	}
	if baseRole != nil {
		_ = s.userRepo.AssignBaseRole(ctx, domain.NewUserBaseRole(user.ID, baseRole.ID, nil))
	}
	s.applyImportTags(ctx, user.ID, user.Namespace, row.NamespaceTags, appTags)
	if app != nil {
		s.ensureAppEntitlements(ctx, user, app, EntitlementOverrides{})
	}
	out.Status, out.UID = "created", user.ID.String()
	return out
}

// applyImportTags tags a user into the union of the app's read pools and any
// per-row namespace_tags, excluding the home pool (which needs no tag row).
func (s *AuthService) applyImportTags(ctx context.Context, userID types.ID, home string, rowTags, appTags []string) {
	seen := map[string]bool{home: true}
	var tags []string
	for _, t := range append(append([]string{}, appTags...), rowTags...) {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		tags = append(tags, t)
	}
	if len(tags) > 0 {
		_ = s.userRepo.AddUserToNamespaces(ctx, userID, tags)
	}
}
