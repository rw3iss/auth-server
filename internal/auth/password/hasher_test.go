package password

import "testing"

func TestRegistryDefaultsToBcrypt(t *testing.T) {
	r := NewRegistry()
	// Empty algo resolves to bcrypt.
	s, ok := r.Get("")
	if !ok || s.Algo() != "bcrypt" {
		t.Fatalf("empty algo should resolve to bcrypt, got ok=%v algo=%q", ok, algoOf(s))
	}
	if !s.VerifiesOnLogin() {
		t.Error("bcrypt must verify on the normal login path")
	}
	if _, ok := r.Get("argon2id"); ok {
		t.Error("unregistered algo should not resolve")
	}
}

func algoOf(s LegacyHashStrategy) string {
	if s == nil {
		return ""
	}
	return s.Algo()
}

func TestBcryptValidate(t *testing.T) {
	s := BcryptStrategy{}
	// A real PHP password_hash($2y$) value (cost 10).
	valid := "$2y$10$N9qo8uLOickgx2ZMRZoMy.MrqOZ0kPdQU5l9V4r0vJ4mC9b5G2pZS"
	if got, err := s.Validate(valid); err != nil || got != valid {
		t.Fatalf("expected valid $2y$ hash to pass, err=%v", err)
	}
	for _, bad := range []string{"", "plaintext", "$1$abc", "$2y$short"} {
		if _, err := s.Validate(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}
