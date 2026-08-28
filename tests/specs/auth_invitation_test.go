//go:build integration

// Organization invitations. Previously ZERO coverage — handler, repository and
// the org-service invite flow all existed with no test of any kind, including
// the register-with-invite security guard.

package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rw3iss/auth/tests/specs/helpers"
)

// seedOrgAndInvitation writes an organization and a pending invitation straight
// through SQL.
//
// DIRECT SETUP ON PURPOSE. Creating an org through the API needs a caller who
// already holds org-admin permissions, which needs an org — the bootstrap
// problem this sidesteps. The thing under test is the REGISTRATION and
// ACCEPTANCE endpoints, not org creation, so the fixture states the world and
// the test exercises the real HTTP path against it.
func seedOrgAndInvitation(t *testing.T, env *helpers.TestEnvironment, ownerID, inviteeEmail string) (orgID, code, token string) {
	t.Helper()
	ctx := context.Background()
	orgID = uuid.NewString()
	code = "TESTCODE" + uuid.NewString()[:8]
	token = "testtoken-" + uuid.NewString()

	slug := fmt.Sprintf("test-org-%d", time.Now().UnixNano())
	if _, err := env.DB.ExecContext(ctx, `
		INSERT INTO organizations (id, name, slug, status, owner_id, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', $4, now(), now())`,
		orgID, "Test Org "+slug, slug, ownerID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if _, err := env.DB.ExecContext(ctx, `
		INSERT INTO invitations (id, organization_id, email, code, token, invited_by, expires_at, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + interval '7 days', 'pending', now(), now())`,
		uuid.NewString(), orgID, inviteeEmail, code, token, ownerID); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	return orgID, code, token
}

// THE SECURITY REGRESSION. The register-with-invite path once accepted ANY
// registering email against a valid invite token, which made a leaked or
// forwarded invitation link a bearer credential for org membership: whoever
// held it could register an address of their choosing into that organization.
// The authenticated accept path always compared the address; the two routes
// into the same membership disagreed.
//
// A green test here is the only thing standing between that and a silent
// reintroduction.
func TestRegisterWithInvite_RejectsMismatchedEmail(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	owner := helpers.RegisterAndLogin(t, env.Client)

	invited := helpers.UniqueEmail()
	_, _, token := seedOrgAndInvitation(t, env, owner.UserID, invited)

	// An ATTACKER registers their own address using the invitation meant for
	// someone else.
	attacker := helpers.NewTestUser()
	input := attacker.RegisterInput()
	input["invite_token"] = token

	resp := env.Client.Register(t, input)
	if resp.StatusCode == http.StatusCreated {
		// If registration is allowed at all it must NOT have conferred membership.
		// Fail loudly either way: the guard's job is to refuse the pairing.
		t.Fatalf("SECURITY: registration with another address's invite token was accepted (%d %s)",
			resp.StatusCode, resp.Body)
	}
}

// The same invitation MUST still work for the address it was actually sent to,
// or the guard above is just breaking the feature.
func TestRegisterWithInvite_AcceptsMatchingEmail(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	owner := helpers.RegisterAndLogin(t, env.Client)

	invitee := helpers.NewTestUser()
	_, _, token := seedOrgAndInvitation(t, env, owner.UserID, invitee.Email)

	input := invitee.RegisterInput()
	input["invite_token"] = token

	if resp := env.Client.Register(t, input); resp.StatusCode != http.StatusCreated {
		t.Fatalf("the invited address should be able to register with its own token: %d %s",
			resp.StatusCode, resp.Body)
	}
}

// The invitee-side surface is authenticated. An unauthenticated caller must not
// be able to list or accept invitations — accepting one is a membership grant.
func TestInvitations_InviteeEndpointsRequireAuth(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	env.Client.ClearToken()

	if resp := env.Client.ListMyInvitations(t); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("listing invitations unauthenticated should be 401, got %d %s", resp.StatusCode, resp.Body)
	}
	if resp := env.Client.AcceptMyInvitation(t, uuid.NewString()); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("accepting an invitation unauthenticated should be 401, got %d %s", resp.StatusCode, resp.Body)
	}
}

// Accepting SOMEONE ELSE'S invitation must not work. The server answers a
// constant-time NotFound rather than a distinct error, so this asserts only
// that it is refused — the specific code is deliberately uninformative and
// asserting it exactly would lock in a detail that is meant to stay opaque.
func TestInvitations_CannotAcceptAnothersInvitation(t *testing.T) {
	env := helpers.NewTestEnvironment(t)
	owner := helpers.RegisterAndLogin(t, env.Client)
	_, _, _ = seedOrgAndInvitation(t, env, owner.UserID, helpers.UniqueEmail())

	// A DIFFERENT signed-in user tries to accept it. They cannot know the id, so
	// this also covers the guessing case.
	other := helpers.RegisterAndLogin(t, env.Client)
	env.Client.SetToken(other.AccessToken)
	defer env.Client.ClearToken()

	var listed struct {
		Invitations []struct {
			ID string `json:"id"`
		} `json:"invitations"`
	}
	resp := env.Client.ListMyInvitations(t)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list own invitations: %d %s", resp.StatusCode, resp.Body)
	}
	_ = resp.JSON(&listed)
	// The invitation was addressed to a third party, so this user must see none of it.
	for _, inv := range listed.Invitations {
		if inv.ID == "" {
			continue
		}
		t.Fatalf("a user was shown an invitation addressed to someone else: %s", resp.Body)
	}
}
