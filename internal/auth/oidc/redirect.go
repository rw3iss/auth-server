package oidc

import (
	"fmt"
	"net/url"
	"strings"
)

// Redirect-URI validation.
//
// THIS IS THE CONTROL THE WHOLE AUTHORIZATION-CODE FLOW RESTS ON. The authorize endpoint delivers a
// user's authorization code to whatever address the client names, and the ONLY thing stopping an
// attacker naming their own address is that it must already appear, character for character, in this
// client's registered list (Client.AllowsRedirect). Everything here exists to make sure the entries in
// that list cannot be written so loosely that the exact match stops meaning anything:
//
//   - A WILDCARD ("https://*.example.com/cb") turns the exact match into a pattern match, and patterns
//     are where credential forwarding lives.
//   - A FRAGMENT is forbidden by RFC 6749 §3.1.2 and, worse, is invisible to the server at request time —
//     the browser never sends it — so it cannot be part of a meaningful comparison.
//   - USERINFO ("https://good.example@evil.example/") is a classic reader-versus-parser trick: a human
//     reviewing the registration sees "good.example", the browser goes to evil.example.
//   - PLAIN HTTP puts the authorization code on the wire in clear text. The single exception is the
//     loopback interface, because a developer has no way to obtain a certificate for it and the code
//     never leaves the machine. That exception is checked on the PARSED HOST, not on a string prefix:
//     "http://localhost.attacker.net/cb" starts with "http://localhost" and is a completely different,
//     attacker-controlled host.
//
// It is deliberately one implementation, shared by the self-service and the administrative registration
// paths. Two copies of a rule this sharp would eventually disagree, and the disagreement would be a hole.
//
// Every function returns a HUMAN-READABLE reason, or "" when the value is acceptable. The reasons are
// surfaced verbatim to whoever is registering the client — they are written to be read by a developer
// who is trying to work out why their URI was refused.

const (
	// MaxRedirectURIs bounds one client's allow-list. Ten distinct callbacks covers a real application
	// (production, staging, a couple of local ports) while keeping the row, and the exact-match scan the
	// authorize endpoint runs on every request, small.
	MaxRedirectURIs = 10

	// maxRedirectURILen bounds one entry. Nothing legitimate is near this.
	maxRedirectURILen = 512
)

// ValidateRedirectURI checks a single redirect URI. Returns "" when it is acceptable.
func ValidateRedirectURI(raw string) string {
	// Control characters are scanned on the RAW value, BEFORE trimming, and surrounding SPACES are then
	// trimmed. The asymmetry is deliberate: a leading/trailing space is an ordinary paste artefact from a
	// config file and costs nothing to absorb, whereas a tab, CR or LF — anywhere, including at the end —
	// is response-splitting material and has no legitimate place in a URL. Trimming those first would
	// silently accept and store them.
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "Redirect URIs must not contain tabs, line breaks or other control characters"
		}
	}
	s := strings.Trim(raw, " ")
	if s == "" {
		return "Redirect URIs cannot be blank"
	}
	if len(s) > maxRedirectURILen {
		return fmt.Sprintf("Redirect URIs must be %d characters or fewer", maxRedirectURILen)
	}
	if strings.Contains(s, " ") {
		return "Redirect URIs must not contain spaces"
	}
	if strings.Contains(s, "*") {
		// Checked on the raw string rather than a parsed component, because a wildcard anywhere —
		// scheme, host, path, query — defeats the exact match.
		return "Wildcards are not allowed in redirect URIs — register each exact address separately"
	}
	if strings.Contains(s, "#") {
		// Also catches a bare trailing "#", which url.Parse reports as an empty fragment.
		return "Redirect URIs must not contain a fragment (the part after #) — the browser never sends it, so it cannot be matched"
	}

	u, err := url.Parse(s)
	if err != nil {
		return "That is not a valid URL"
	}
	if u.Opaque != "" || !strings.Contains(s, "://") {
		return "Redirect URIs must be absolute, starting with https:// (or http:// for localhost)"
	}
	if u.Scheme == "" || u.Host == "" {
		return "Redirect URIs must be absolute, starting with https:// (or http:// for localhost)"
	}
	if u.User != nil {
		return "Redirect URIs must not contain a username or password"
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "Redirect URIs must name a host"
	}

	switch u.Scheme {
	case "https":
		// The normal case. Any https host is acceptable — proving control of it is the registrant's
		// problem, and exact matching is what makes it safe for us.
	case "http":
		if !isLoopbackHost(host) {
			return "Redirect URIs must use https — plain http is allowed only for local development (http://localhost or http://127.0.0.1, with any port)"
		}
	default:
		return "Redirect URIs must use https — custom schemes are not accepted"
	}
	return ""
}

// isLoopbackHost reports the three spellings of "this machine".
//
// An EXACT host comparison, never a prefix: "localhost.attacker.net" and "127.0.0.1.attacker.net" are
// ordinary registrable domains that a prefix test happily accepts, which would hand every authorization
// code issued to that client to whoever owns them.
func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// ValidateRedirectURIs checks a whole list and requires at least one.
//
// Refusing an empty list is a usability decision as much as a security one: a client with no redirect URI
// cannot complete a single login, and the registrant would otherwise discover that only when their first
// user hit an error they could not read.
func ValidateRedirectURIs(uris []string) string {
	if len(uris) == 0 {
		return "At least one redirect URI is required"
	}
	return validateURIList(uris, "redirect")
}

// ValidatePostLogoutURIs applies the same rules, but an empty list is fine — post-logout redirection is
// optional, and a client that does not use it should not be forced to invent an address.
func ValidatePostLogoutURIs(uris []string) string {
	if len(uris) == 0 {
		return ""
	}
	return validateURIList(uris, "post-logout")
}

func validateURIList(uris []string, kind string) string {
	if len(uris) > MaxRedirectURIs {
		return fmt.Sprintf("At most %d %s URIs per application", MaxRedirectURIs, kind)
	}
	for _, raw := range uris {
		if msg := ValidateRedirectURI(raw); msg != "" {
			return msg + " — check " + quoteForMessage(raw)
		}
	}
	return ""
}

// NormalizeURIs trims each entry and drops exact duplicates, PRESERVING ORDER and preserving the value
// otherwise byte for byte.
//
// Nothing beyond trimming and de-duplication: the stored string is the one the authorize endpoint
// compares against, so "helpfully" lowercasing a host or dropping a trailing slash would silently store
// something the client will never send, and every login through it would fail with a redirect_uri
// mismatch the registrant did not cause.
func NormalizeURIs(uris []string) []string {
	out := make([]string, 0, len(uris))
	seen := make(map[string]bool, len(uris))
	for _, raw := range uris {
		// Trims SPACES only, matching ValidateRedirectURI exactly. Using TrimSpace here would strip a
		// trailing tab or CR before the validator ever saw it, so a control character would be silently
		// accepted purely because normalisation runs first.
		s := strings.Trim(raw, " ")
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// quoteForMessage echoes the offending value back, truncated. It is the caller's own input, so there is
// nothing to disclose — but an unbounded echo is a free amplification primitive in a log line.
func quoteForMessage(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return `"` + s + `"`
}
