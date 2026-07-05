package domain

// ExcludeHomeNamespace returns the read pools a user should be tagged into
// (user_namespaces membership), excluding their home pool — the home namespace
// lives on users.namespace and needs no tag row. Pure set op; empty entries
// are dropped. Used by every provisioning path (register / login / SSO / JIT
// migration / bulk import) so the tag set is computed one way. See
// docs/USER_POOLS.md.
func ExcludeHomeNamespace(readNamespaces []string, home string) []string {
	out := make([]string, 0, len(readNamespaces))
	for _, ns := range readNamespaces {
		if ns != "" && ns != home {
			out = append(out, ns)
		}
	}
	return out
}
