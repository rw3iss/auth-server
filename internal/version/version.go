// Package version exposes the auth-server build version. The const
// is the single source of truth for what `auth-docs`'s release
// tooling reads (see `auth-docs/scripts/gen-versions.ts`) and what
// the server reports at `/health` and in audit logs.
//
// Bump on every release. The Vendidit auth platform follows a
// coordinated-minor / independent-patch model — see auth-docs's
// "Releasing" section for the workflow.
package version

// Version is the auth-server's SemVer string.
const Version = "0.7.0"
