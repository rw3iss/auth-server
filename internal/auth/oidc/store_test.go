package oidc

import (
	"testing"

	"github.com/lib/pq"
)

func TestAllowsOriginMatchesARegisteredRedirectURI(t *testing.T) {
	c := &Client{
		RedirectURIs:   pq.StringArray{"https://rp.example/auth/callback", "http://localhost:4321/auth/callback"},
		PostLogoutURIs: pq.StringArray{"https://logout.example/"},
	}
	for _, origin := range []string{
		"https://rp.example",
		"http://localhost:4321",
		// Post-logout URIs count too: they are origins the client already proved it
		// controls, registered through the same administrative gate.
		"https://logout.example",
	} {
		if !c.AllowsOrigin(origin) {
			t.Fatalf("AllowsOrigin(%q) = false, want true", origin)
		}
	}
}

func TestAllowsOriginRejectsEverythingElse(t *testing.T) {
	c := &Client{RedirectURIs: pq.StringArray{"https://rp.example/auth/callback"}}
	for _, origin := range []string{
		"",
		"https://evil.example",
		// The classic prefix-match hole. A suffix-tolerant comparison accepts this and
		// hands the token to whoever registered rp.example.attacker.net.
		"https://rp.example.attacker.net",
		"http://rp.example", // scheme must match — http is not https
		"https://rp.example:8443",
		"not a url",
	} {
		if c.AllowsOrigin(origin) {
			t.Fatalf("AllowsOrigin(%q) = true, want false", origin)
		}
	}
}

func TestAllowsOriginIgnoresTheDefaultPort(t *testing.T) {
	// A browser's Origin header never carries the default port, but a registered
	// redirect URI reasonably might. Treating those as different would reject a
	// legitimate relying party for a reason nothing in the response explains.
	c := &Client{RedirectURIs: pq.StringArray{"https://rp.example:443/cb", "http://dev.example:80/cb"}}
	if !c.AllowsOrigin("https://rp.example") {
		t.Fatal("https default port should normalise away")
	}
	if !c.AllowsOrigin("http://dev.example") {
		t.Fatal("http default port should normalise away")
	}
}

func TestAllowsOriginIsCaseInsensitiveOnHost(t *testing.T) {
	c := &Client{RedirectURIs: pq.StringArray{"https://RP.Example/cb"}}
	if !c.AllowsOrigin("https://rp.example") {
		t.Fatal("host comparison must be case-insensitive")
	}
}

func TestPrimaryOrigin(t *testing.T) {
	c := &Client{RedirectURIs: pq.StringArray{"https://rp.example/auth/callback"}}
	if got := c.PrimaryOrigin(); got != "https://rp.example" {
		t.Fatalf("PrimaryOrigin() = %q", got)
	}
	empty := &Client{}
	if got := empty.PrimaryOrigin(); got != "" {
		t.Fatalf("PrimaryOrigin() = %q, want empty for a client with no redirect URIs", got)
	}
	// A junk entry must not become an origin — it would end up in client metadata as
	// a link we told the browser was that company's privacy policy.
	junk := &Client{RedirectURIs: pq.StringArray{"not-a-url", "https://ok.example/cb"}}
	if got := junk.PrimaryOrigin(); got != "https://ok.example" {
		t.Fatalf("PrimaryOrigin() = %q, want the first PARSEABLE origin", got)
	}
}
