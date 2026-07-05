package postgres

import "testing"

// AUDIT 1.21: the resolver must reject anything not in the allowlist (the
// SQL-injection vector) and force the direction to ASC/DESC.
func TestResolveSort(t *testing.T) {
	allow := []string{"created_at", "email", "first_name"}

	cases := []struct {
		name, requested, requestedOrder string
		wantCol, wantOrd                 string
	}{
		{"empty falls back", "", "", "created_at", "ASC"},
		{"case-insensitive match", "EMAIL", "desc", "email", "DESC"},
		{"unknown column falls back", "password_hash", "ASC", "created_at", "ASC"},
		{"SQL injection rejected", "created_at;DROP TABLE users--", "ASC", "created_at", "ASC"},
		{"weird casing/whitespace direction", "first_name", "  Desc  ", "first_name", "DESC"},
		{"junk direction = ASC", "email", "blah", "email", "ASC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			col, ord := resolveSort(tc.requested, "created_at", tc.requestedOrder, allow)
			if col != tc.wantCol || ord != tc.wantOrd {
				t.Fatalf("got (%q, %q), want (%q, %q)", col, ord, tc.wantCol, tc.wantOrd)
			}
		})
	}
}
