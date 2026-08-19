package oidc

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ── Scopes ────────────────────────────────────────────────────────────────────────────────────────────
//
// The civic scopes are deliberately NARROW. `civic:positions` and `civic:activity` carry political-belief
// data about a private individual — who they contacted, what they urged, what they have declared. Bundling
// those into a broad "profile" scope would mean a relying party asking for a display name silently
// receives someone's political record. They are separate so consent can be separate.
const (
	ScopeOpenID     = "openid"
	ScopeProfile    = "profile"
	ScopeEmail      = "email"
	ScopeOffline    = "offline_access"
	ScopeCivicLoc   = "civic:location"
	ScopeCivicInt   = "civic:interests"
	ScopePositions  = "civic:positions"
	ScopeCivicActiv = "civic:activity"
)

// SupportedScopes is advertised in discovery and is the allow-list for an authorization request.
var SupportedScopes = []string{
	ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOffline,
	ScopeCivicLoc, ScopeCivicInt, ScopePositions, ScopeCivicActiv,
}

// SensitiveScopes always require an explicit consent interaction, even for a client that was previously
// approved for the others. Silence must never be read as consent for political-belief data.
var SensitiveScopes = map[string]bool{
	ScopePositions:  true,
	ScopeCivicActiv: true,
}

// ParseScopes splits a space-delimited scope string and drops anything unsupported.
//
// Dropping unknown scopes rather than erroring follows RFC 6749 §3.3: the server MAY ignore scopes it does
// not recognise. The granted set is echoed back in the token response, so a client can always see exactly
// what it received rather than assuming it got what it asked for.
func ParseScopes(raw string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range strings.Fields(raw) {
		for _, ok := range SupportedScopes {
			if s == ok && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// HasScope reports whether the granted set contains one scope.
func HasScope(granted []string, want string) bool {
	for _, s := range granted {
		if s == want {
			return true
		}
	}
	return false
}

// ── ID token ──────────────────────────────────────────────────────────────────────────────────────────

// IDTokenClaims is the OIDC Core §2 standard claim set plus the CivicGate additions.
//
// Standard names matter more than they look: `sub`, `aud`, `iss`, `email_verified` and friends are what
// every OIDC library reads automatically. Inventing our own names for the same facts is exactly what makes
// an identity provider need a bespoke client.
type IDTokenClaims struct {
	jwt.RegisteredClaims

	Nonce    string `json:"nonce,omitempty"`
	AuthTime int64  `json:"auth_time,omitempty"`
	AZP      string `json:"azp,omitempty"` // authorized party — the client this was minted for

	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Preferred     string `json:"preferred_username,omitempty"`
	Picture       string `json:"picture,omitempty"`
	UpdatedAt     int64  `json:"updated_at,omitempty"`

	// CivicGate additions, namespaced so they cannot collide with a future standard claim.
	AppCode    string   `json:"cg_app_code,omitempty"`
	Namespaces []string `json:"cg_namespaces,omitempty"`
	Roles      []string `json:"cg_roles,omitempty"`
}

// IDTokenInput is everything needed to mint an ID token.
type IDTokenInput struct {
	Issuer     string
	Subject    string
	Audience   string
	Nonce      string
	AuthTime   time.Time
	TTL        time.Duration
	Scopes     []string
	Email      string
	EmailVerif bool
	Name       string
	GivenName  string
	FamilyName string
	Username   string
	Picture    string
	AppCode    string
	Namespaces []string
	Roles      []string
}

// NewIDToken mints and signs an ID token with RS256.
//
// CLAIMS ARE FILTERED BY SCOPE. A client that asked only for `openid` gets a subject and nothing else —
// not the email, not the name. That is the difference between a consent screen that means something and
// one that is decoration.
func (km *KeyManager) NewIDToken(in IDTokenInput) (string, error) {
	now := time.Now()
	ttl := in.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute // OIDC ID tokens are short-lived by design; they are proof of a login event.
	}

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    in.Issuer,
			Subject:   in.Subject,
			Audience:  jwt.ClaimStrings{in.Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
		},
		Nonce:      in.Nonce,
		AZP:        in.Audience,
		AppCode:    in.AppCode,
		Namespaces: in.Namespaces,
	}
	if !in.AuthTime.IsZero() {
		claims.AuthTime = in.AuthTime.Unix()
	}
	if HasScope(in.Scopes, ScopeEmail) {
		claims.Email = in.Email
		claims.EmailVerified = in.EmailVerif
	}
	if HasScope(in.Scopes, ScopeProfile) {
		claims.Name = in.Name
		claims.GivenName = in.GivenName
		claims.FamilyName = in.FamilyName
		claims.Preferred = in.Username
		claims.Picture = in.Picture
		claims.Roles = in.Roles
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// The kid header is what lets a verifier pick the right JWKS entry without trial-and-error, and is
	// what makes key rotation a non-event for relying parties.
	tok.Header["kid"] = km.KID()
	signed, err := tok.SignedString(km.PrivateKey())
	if err != nil {
		return "", fmt.Errorf("signing id_token: %w", err)
	}
	return signed, nil
}

// VerifyIDToken parses and validates a token this server issued. Provided so first-party services (and
// tests) can verify without duplicating the key plumbing.
func (km *KeyManager) VerifyIDToken(tokenString, issuer, audience string) (*IDTokenClaims, error) {
	claims := &IDTokenClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			// Refusing a non-RSA algorithm is what closes the `alg: none` and HMAC-confusion attacks,
			// where an attacker re-signs a token with the PUBLIC key as an HMAC secret.
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return &km.PrivateKey().PublicKey, nil
	}, jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	return claims, nil
}
