package oidc

import (
	"strings"
	"testing"
)

// THE REDIRECT-URI VALIDATOR IS ONE OF THE TWO THINGS IN SELF-SERVICE REGISTRATION THAT MUST NOT
// REGRESS. Everything the authorization-code flow does to keep a user's session away from an attacker
// reduces, in the end, to "the address the code is delivered to already appears, exactly, in this
// client's registered list". If a value that is not really an exact, https, developer-controlled address
// can get INTO that list, the exact match downstream is checking the wrong thing perfectly.
//
// So these cases are written as the attacks they prevent, not as a shape checklist.

func TestValidateRedirectURIAcceptsOrdinaryHTTPS(t *testing.T) {
	for _, uri := range []string{
		"https://example.com/auth/callback",
		"https://sub.domain.example.co.uk/cb",
		"https://example.com:8443/cb",
		// A query component is legal (RFC 6749 §3.1.2) and exact matching handles it safely.
		"https://example.com/cb?tenant=acme",
		// A bare origin is a legitimate callback.
		"https://example.com",
		// Trailing whitespace is trimmed, not rejected — pasting from a config file is not an attack.
		"  https://example.com/cb  ",
	} {
		if msg := ValidateRedirectURI(uri); msg != "" {
			t.Errorf("ValidateRedirectURI(%q) = %q, want accepted", uri, msg)
		}
	}
}

func TestValidateRedirectURIAcceptsLoopbackOverPlainHTTP(t *testing.T) {
	// A developer cannot obtain a certificate for their own machine, and the code never leaves it.
	for _, uri := range []string{
		"http://localhost/cb",
		"http://localhost:4321/auth/callback",
		"http://127.0.0.1:3000/cb",
		"http://[::1]:8080/cb",
		"http://LOCALHOST:4321/cb", // host comparison is case-insensitive
		"https://localhost:4321/cb",
	} {
		if msg := ValidateRedirectURI(uri); msg != "" {
			t.Errorf("ValidateRedirectURI(%q) = %q, want accepted", uri, msg)
		}
	}
}

// THE ONE THAT MATTERS MOST. The rule this replaced tested `strings.HasPrefix(s, "http://localhost")`,
// which accepts every host below: they are ordinary registrable domains an attacker can own, reached
// over plain http, that merely START with the text "localhost" or "127.0.0.1". Registering one would
// deliver every authorization code issued to that client to its owner, in the clear.
func TestValidateRedirectURIRejectsHostsThatMerelyLookLoopback(t *testing.T) {
	for _, uri := range []string{
		"http://localhost.attacker.net/cb",
		"http://localhost.evil.example/cb",
		"http://127.0.0.1.attacker.net/cb",
		"http://localhosting.example/cb",
		"http://127.0.0.10/cb",
		// Userinfo makes the *authority* read as localhost to a human skimming the registration form
		// while the browser resolves attacker.net.
		"http://localhost@attacker.net/cb",
	} {
		if msg := ValidateRedirectURI(uri); msg == "" {
			t.Errorf("ValidateRedirectURI(%q) = accepted, want rejected — this is a remote host over plain http", uri)
		}
	}
}

func TestValidateRedirectURIRejectsWildcards(t *testing.T) {
	// A wildcard turns the exact match into a pattern match, and patterns are where credential
	// forwarding lives. Rejected wherever it appears, not just in the host.
	for _, uri := range []string{
		"https://*.example.com/cb",
		"https://example.com/*",
		"https://example.com/cb?next=*",
		"*",
	} {
		msg := ValidateRedirectURI(uri)
		if msg == "" {
			t.Errorf("ValidateRedirectURI(%q) = accepted, want rejected", uri)
			continue
		}
		if !strings.Contains(strings.ToLower(msg), "wildcard") && !strings.Contains(strings.ToLower(msg), "absolute") {
			t.Errorf("ValidateRedirectURI(%q) = %q, want a message a developer can act on", uri, msg)
		}
	}
}

func TestValidateRedirectURIRejectsPathPrefixesAndRelativeForms(t *testing.T) {
	// Nothing here names a host, so nothing here can be matched against what a browser sends.
	for _, uri := range []string{
		"/auth/callback",
		"auth/callback",
		"example.com/cb",
		"//example.com/cb",
		"https:///cb",
		"https://",
		"mailto:someone@example.com",
	} {
		if msg := ValidateRedirectURI(uri); msg == "" {
			t.Errorf("ValidateRedirectURI(%q) = accepted, want rejected", uri)
		}
	}
}

func TestValidateRedirectURIRejectsFragments(t *testing.T) {
	// RFC 6749 §3.1.2 forbids them, and the browser never sends the fragment anyway — so a registered
	// fragment could not participate in a comparison even if we wanted it to.
	for _, uri := range []string{
		"https://example.com/cb#",
		"https://example.com/cb#token",
		"https://example.com/#/callback",
	} {
		if msg := ValidateRedirectURI(uri); msg == "" {
			t.Errorf("ValidateRedirectURI(%q) = accepted, want rejected", uri)
		}
	}
}

func TestValidateRedirectURIRejectsCredentialsInTheAuthority(t *testing.T) {
	// The reader-versus-parser trick: a human reviewing the registration sees "good.example", the
	// browser goes to evil.example.
	for _, uri := range []string{
		"https://good.example@evil.example/cb",
		"https://user:password@example.com/cb",
	} {
		if msg := ValidateRedirectURI(uri); msg == "" {
			t.Errorf("ValidateRedirectURI(%q) = accepted, want rejected", uri)
		}
	}
}

func TestValidateRedirectURIRejectsNonHTTPSchemes(t *testing.T) {
	for _, uri := range []string{
		"javascript:alert(1)",
		"data:text/html,<script>",
		"file:///etc/passwd",
		"ftp://example.com/cb",
		"myapp://callback",
		"HTTP://attacker.net/cb", // scheme case must not smuggle plain http past the check
	} {
		if msg := ValidateRedirectURI(uri); msg == "" {
			t.Errorf("ValidateRedirectURI(%q) = accepted, want rejected", uri)
		}
	}
}

func TestValidateRedirectURIRejectsBlankAndOversizedAndControlCharacters(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"https://example.com/cb with a space",
		"https://example.com/cb\nLocation: https://attacker.net",
		"https://example.com/cb\r\n",
		"https://example.com/cb\t",
		"https://example.com/" + strings.Repeat("a", maxRedirectURILen),
	}
	for _, uri := range cases {
		if msg := ValidateRedirectURI(uri); msg == "" {
			t.Errorf("ValidateRedirectURI(%q) = accepted, want rejected", uri)
		}
	}
}

func TestValidateRedirectURIsRequiresAtLeastOne(t *testing.T) {
	// A client with no redirect URI cannot complete a single login; refusing at registration is the only
	// point where the registrant can be told so in words.
	if msg := ValidateRedirectURIs(nil); msg == "" {
		t.Fatal("an empty redirect list must be rejected")
	}
	if msg := ValidateRedirectURIs([]string{}); msg == "" {
		t.Fatal("an empty redirect list must be rejected")
	}
}

func TestValidateRedirectURIsRejectsTheWholeListWhenAnyEntryIsBad(t *testing.T) {
	// A per-entry rule that passes as long as SOME entry is fine would let an attacker append their
	// address to a legitimate list. The list is accepted or it is not.
	list := []string{
		"https://good.example/cb",
		"https://*.attacker.net/cb",
		"https://also-good.example/cb",
	}
	msg := ValidateRedirectURIs(list)
	if msg == "" {
		t.Fatal("a list containing a wildcard must be rejected")
	}
	// And the message must name the offender, or the developer has to bisect their own form.
	if !strings.Contains(msg, "attacker.net") {
		t.Errorf("message %q should identify which URI was refused", msg)
	}
}

func TestValidateRedirectURIsCapsTheListLength(t *testing.T) {
	many := make([]string, MaxRedirectURIs+1)
	for i := range many {
		many[i] = "https://example.com/cb" + string(rune('a'+i))
	}
	if msg := ValidateRedirectURIs(many); msg == "" {
		t.Fatalf("a list of %d must be rejected (cap is %d)", len(many), MaxRedirectURIs)
	}
	ok := many[:MaxRedirectURIs]
	if msg := ValidateRedirectURIs(ok); msg != "" {
		t.Fatalf("a list of exactly %d must be accepted, got %q", MaxRedirectURIs, msg)
	}
}

func TestValidatePostLogoutURIsAllowsEmptyButAppliesTheSameRules(t *testing.T) {
	if msg := ValidatePostLogoutURIs(nil); msg != "" {
		t.Fatalf("post-logout URIs are optional, got %q", msg)
	}
	if msg := ValidatePostLogoutURIs([]string{"http://attacker.net/bye"}); msg == "" {
		t.Fatal("post-logout URIs are redirect targets too and must be validated identically")
	}
}

func TestNormalizeURIsTrimsAndDeduplicatesWithoutRewriting(t *testing.T) {
	in := []string{
		"  https://example.com/cb  ",
		"https://example.com/cb",
		"",
		"https://Example.com/CB",
	}
	got := NormalizeURIs(in)
	want := []string{"https://example.com/cb", "https://Example.com/CB"}
	if len(got) != len(want) {
		t.Fatalf("NormalizeURIs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			// Case and trailing slashes are NOT normalised on purpose: the stored string is what the
			// authorize endpoint compares against, so silently rewriting it would store something the
			// client never sends and break every login with a mismatch the registrant did not cause.
			t.Fatalf("NormalizeURIs[%d] = %q, want %q — values must be preserved byte for byte", i, got[i], want[i])
		}
	}
}

func TestIsLoopbackHostIsAnExactComparison(t *testing.T) {
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{
		"localhost.attacker.net", "127.0.0.1.attacker.net", "notlocalhost",
		"localhost2", "127.0.0.2", "::2", "",
	} {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}
