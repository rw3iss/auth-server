// Package password decouples legacy password-hash *formats* from the
// auth-server core (the "app-agnostic strategy" of the bulk-import spec, §4).
//
// The login verify path uses bcrypt.CompareHashAndPassword, so any app whose
// legacy store is bcrypt (GlobalSKU, ClaimLeo, …) imports verbatim and Just
// Works. Other algorithms register a strategy here; the core never hard-codes
// a single app's scheme.
package password

import (
	"fmt"
	"strings"
)

// LegacyHashStrategy validates a pre-hashed credential for import. It never
// re-hashes — the whole point of a cutover import is that stored hashes are
// preserved verbatim so existing passwords keep working with no reset.
type LegacyHashStrategy interface {
	// Algo is the registry key, e.g. "bcrypt". Lowercase.
	Algo() string

	// Validate confirms the hash is well-formed for this algorithm and
	// returns the value to store verbatim. An error rejects the row.
	Validate(hash string) (string, error)

	// VerifiesOnLogin reports whether a hash stored under this algorithm will
	// authenticate through the standard login path (bcrypt) with no extra
	// wiring. true for bcrypt; false for algorithms that need a registered
	// verifier or a JIT re-hash on next login.
	VerifiesOnLogin() bool
}

// Registry maps hash_algo → strategy. bcrypt is registered by default.
type Registry struct {
	strategies map[string]LegacyHashStrategy
}

// NewRegistry returns a registry preloaded with the bcrypt strategy.
func NewRegistry() *Registry {
	r := &Registry{strategies: map[string]LegacyHashStrategy{}}
	r.Register(BcryptStrategy{})
	return r
}

// Register adds (or replaces) a strategy. Not safe for concurrent use; wire
// all strategies at boot before serving requests.
func (r *Registry) Register(s LegacyHashStrategy) {
	r.strategies[strings.ToLower(s.Algo())] = s
}

// Get resolves a strategy by algo (case-insensitive). Empty algo ⇒ "bcrypt".
func (r *Registry) Get(algo string) (LegacyHashStrategy, bool) {
	algo = strings.ToLower(strings.TrimSpace(algo))
	if algo == "" {
		algo = "bcrypt"
	}
	s, ok := r.strategies[algo]
	return s, ok
}

// BcryptStrategy is the default. bcrypt hashes embed their cost, so they're
// portable across servers and verify immediately via the existing login path.
type BcryptStrategy struct{}

func (BcryptStrategy) Algo() string          { return "bcrypt" }
func (BcryptStrategy) VerifiesOnLogin() bool { return true }

// Validate accepts the three bcrypt variants ($2a$ / $2b$ / $2y$). PHP's
// password_hash emits $2y$; Go's golang.org/x/crypto/bcrypt accepts all three.
func (BcryptStrategy) Validate(hash string) (string, error) {
	h := strings.TrimSpace(hash)
	if len(h) < 60 {
		return "", fmt.Errorf("bcrypt hash too short")
	}
	if !strings.HasPrefix(h, "$2a$") && !strings.HasPrefix(h, "$2b$") && !strings.HasPrefix(h, "$2y$") {
		return "", fmt.Errorf("not a bcrypt hash (expected $2a/$2b/$2y prefix)")
	}
	return h, nil
}
