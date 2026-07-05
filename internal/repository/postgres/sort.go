package postgres

import "strings"

// AUDIT 1.21: SQL injection via ORDER BY interpolation.
//
// Every list-endpoint in the admin API accepts `sort_by` and `sort_order`
// from the query string and interpolated them straight into the SQL via
// fmt.Sprintf. A system_admin token presenting
// `?sort_by=created_at;DROP TABLE users--` would feed unescaped input into
// the SQL string. Admin-only exposure, but a stolen system_admin token then
// becomes a one-shot DB takeover.
//
// resolveSort takes the user-supplied values plus a per-repository allowlist
// and returns canonical values that are safe to interpolate. Anything not in
// the allowlist falls back to the default. Sort direction is forced to ASC
// or DESC.

// sortOrder normalises a direction string. Anything other than DESC
// (case-insensitive) becomes ASC.
func sortOrder(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "DESC") {
		return "DESC"
	}
	return "ASC"
}

// resolveSort returns a (column, direction) pair that's safe to interpolate
// into an ORDER BY clause. `requested` is the user-supplied column name;
// `defaultCol` is what to use when requested is empty or not in the
// allowlist; `allow` is the set of acceptable column names (canonical form,
// usually snake_case).
func resolveSort(requested, defaultCol, requestedOrder string, allow []string) (string, string) {
	col := defaultCol
	req := strings.TrimSpace(requested)
	if req != "" {
		for _, allowed := range allow {
			if strings.EqualFold(req, allowed) {
				col = allowed
				break
			}
		}
	}
	return col, sortOrder(requestedOrder)
}
