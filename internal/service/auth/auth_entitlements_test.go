package auth

import "testing"

// The privilege-escalation guard: a client-supplied (or app-config) role code
// that names a platform role must be refused so provisioning can never grant
// system_admin / super_admin / base_user in an org. Org roles pass through.
func TestIsPlatformRoleCode(t *testing.T) {
	platform := []string{"system_admin", "SYSTEM_ADMIN", " super_admin ", "base_user"}
	for _, c := range platform {
		if !isPlatformRoleCode(c) {
			t.Errorf("%q should be refused as a platform role", c)
		}
	}
	org := []string{"org_admin", "org_manager", "org_member", "custom_role", ""}
	for _, c := range org {
		if isPlatformRoleCode(c) {
			t.Errorf("%q should NOT be flagged as a platform role", c)
		}
	}
}
