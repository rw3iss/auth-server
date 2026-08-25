package oidc

import "testing"

// AllowsGrant is the check that makes `grant_types` mean anything. It was absent, so the column was
// decoration; these pin the three behaviours that matter.
func TestAllowsGrant(t *testing.T) {
	cases := []struct {
		name   string
		grants []string
		grant  string
		want   bool
	}{
		// An EMPTY array is a row written before enforcement existed. It must mean "the old default",
		// not "nothing" — the alternative locks out every client registered before this change.
		{"empty means default: authorization_code", nil, GrantAuthorizationCode, true},
		{"empty means default: refresh_token", nil, GrantRefreshToken, true},
		{"empty does NOT mean client_credentials", nil, GrantClientCredentials, false},

		{"explicit grant allowed", []string{GrantAuthorizationCode}, GrantAuthorizationCode, true},
		{"grant not listed is refused", []string{GrantAuthorizationCode}, GrantClientCredentials, false},
		{"refresh not listed is refused", []string{GrantAuthorizationCode}, GrantRefreshToken, false},
		{"client_credentials when granted", []string{GrantClientCredentials}, GrantClientCredentials, true},
		{"unknown grant is never allowed", []string{GrantAuthorizationCode}, "implicit", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl := &Client{GrantTypes: c.grants}
			if got := cl.AllowsGrant(c.grant); got != c.want {
				t.Fatalf("AllowsGrant(%q) with %v = %v, want %v", c.grant, c.grants, got, c.want)
			}
		})
	}
}

// The discovery document is built from SupportedGrants. Advertising a grant the token endpoint does not
// serve sends every standards-compliant client down a path that can only fail — which is precisely what
// happened with refresh_token.
func TestSupportedGrantsMatchesWhatWeServe(t *testing.T) {
	for _, g := range []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials} {
		if !IsSupportedGrant(g) {
			t.Fatalf("%s is served by the token endpoint but missing from SupportedGrants", g)
		}
	}
	if IsSupportedGrant("implicit") || IsSupportedGrant("password") {
		t.Fatal("SupportedGrants advertises a grant this server does not implement")
	}
	if len(SupportedGrants) != 3 {
		t.Fatalf("SupportedGrants has %d entries; update this test when the token endpoint changes", len(SupportedGrants))
	}
}

// The default must stay narrow: an interactive application needs these two and nothing more.
func TestDefaultGrantsExcludeClientCredentials(t *testing.T) {
	for _, g := range DefaultGrants {
		if g == GrantClientCredentials {
			t.Fatal("client_credentials must never be a DEFAULT — it authenticates a service with no user present")
		}
	}
}

// offline_access gates the refresh token (OIDC Core §11). It previously gated nothing — the scope was
// read only for its consent-screen label and the refresh token came back regardless, granting repeated
// re-authentication to a client that never asked and a user who was never prompted.
func TestOfflineAccessGatesRefresh(t *testing.T) {
	confidential := &Client{GrantTypes: []string{GrantAuthorizationCode, GrantRefreshToken}}
	codeOnly := &Client{GrantTypes: []string{GrantAuthorizationCode}}

	cases := []struct {
		name   string
		client *Client
		scopes []string
		want   bool
	}{
		{"asked and registered → refresh token", confidential, []string{ScopeOpenID, ScopeOffline}, true},
		{"did not ask → none", confidential, []string{ScopeOpenID, ScopeProfile}, false},
		{"asked but not registered for the grant → none", codeOnly, []string{ScopeOpenID, ScopeOffline}, false},
		{"no scopes at all → none", confidential, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Mirrors the condition in the authorization_code response.
			got := HasScope(c.scopes, ScopeOffline) && c.client.AllowsGrant(GrantRefreshToken)
			if got != c.want {
				t.Fatalf("refresh issued = %v, want %v", got, c.want)
			}
		})
	}
}

// Registration validates scopes for the same reason it validates grants: an unknown scope stored on a
// client is one a consent screen lists and a token never carries.
func TestIsSupportedScope(t *testing.T) {
	for _, s := range SupportedScopes {
		if !IsSupportedScope(s) {
			t.Fatalf("%s is in SupportedScopes but IsSupportedScope says no", s)
		}
	}
	for _, s := range []string{"users:read", "admin", "", "OPENID"} {
		if IsSupportedScope(s) {
			t.Fatalf("IsSupportedScope accepted %q, which this server does not implement", s)
		}
	}
}
