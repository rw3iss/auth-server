package handlers

import (
	"strings"
	"testing"

	"github.com/rw3iss/auth/internal/auth/oidc"
)

// A self-service registration must not be able to grant itself elevated access. The scope list is the
// only place it could try: everything else privileged (trusted, app_code, require_pkce, grant_types) is
// simply not in the statement the store runs.

func TestResolveSelfServiceScopesDefaultsToIdentityOnly(t *testing.T) {
	got, msg := resolveSelfServiceScopes(nil)
	if msg != "" {
		t.Fatalf("unexpected rejection: %s", msg)
	}
	if strings.Join(got, " ") != "openid profile email" {
		t.Fatalf("default scopes = %v, want the three identity scopes", got)
	}
}

func TestResolveSelfServiceScopesRejectsPrivilegedScopes(t *testing.T) {
	// civic:* reads a member's location, declared political positions and activity — data nobody agreed
	// to hand to a stranger who filled in a registration form. offline_access is standing, long-lived
	// access. Both stay administrator-granted.
	for _, scope := range []string{
		"civic:location", "civic:interests", "civic:positions", "civic:activity",
		"offline_access", "admin", "*", "openid profile civic:positions",
	} {
		got, msg := resolveSelfServiceScopes([]string{"openid", scope})
		if msg == "" {
			t.Errorf("resolveSelfServiceScopes([openid %q]) accepted → %v, want rejected", scope, got)
			continue
		}
		// REJECTED, not silently dropped. A silent drop leaves the developer with a client that authorises
		// fine and then returns a token missing the claim they asked for, with nothing explaining why.
		if !strings.Contains(msg, "openid, profile, email") {
			t.Errorf("message %q should tell the developer what IS allowed", msg)
		}
	}
}

func TestResolveSelfServiceScopesAlwaysIncludesOpenIDAndDeduplicates(t *testing.T) {
	// openid is what makes it an OIDC request at all; a client that omitted it would get an OAuth token
	// with no id_token and no obvious reason.
	got, msg := resolveSelfServiceScopes([]string{"email", "email", "profile"})
	if msg != "" {
		t.Fatalf("unexpected rejection: %s", msg)
	}
	if got[0] != oidc.ScopeOpenID {
		t.Fatalf("scopes = %v, want openid first", got)
	}
	seen := map[string]int{}
	for _, s := range got {
		seen[s]++
		if seen[s] > 1 {
			t.Fatalf("scopes = %v, %q repeated", got, s)
		}
	}
}

func TestValidateLogoURLRequiresHTTPS(t *testing.T) {
	// The logo renders on OUR consent screen. A javascript: or data: URL there is stored XSS on the
	// origin that holds the session; plain http is a mixed-content warning on the page where a person is
	// deciding whether to trust the application.
	if msg := validateLogoURL(""); msg != "" {
		t.Fatalf("an absent logo is fine, got %q", msg)
	}
	if msg := validateLogoURL("https://example.com/logo.png"); msg != "" {
		t.Fatalf("https logo rejected: %s", msg)
	}
	for _, bad := range []string{
		"http://example.com/logo.png",
		"javascript:alert(1)",
		"data:image/svg+xml;base64,PHN2Zz4=",
		"//example.com/logo.png",
		"https://example.com/" + strings.Repeat("a", 600),
	} {
		if msg := validateLogoURL(bad); msg == "" {
			t.Errorf("validateLogoURL(%q) accepted, want rejected", truncate(bad, 40))
		}
	}
}
