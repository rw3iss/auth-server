# auth-server tests

## Layers

The auth-server has three layers of tests; pick the one that matches what you're changing.

### Unit (`go test ./internal/... ./pkg/...`)

No build tag. Runs in milliseconds, no external dependencies. Use the in-memory cache/repo stubs in `internal/{audit,auth/jwt,background,logging}/*_test.go` and `pkg/migration/migration_test.go`. Always green on `main`.

### Integration (`make test-integration`)

Build tag: `integration`. Spins up Postgres + Redis via Docker, runs the suites in `tests/specs/*.go`. Exercises the full HTTP surface end-to-end. Cleanup runs between tests via helpers in `tests/specs/helpers/setup.go`. Hermetic — no network calls outside the docker network.

### Cognito migration (`go test -tags integration_cognito ./tests/specs/...`)

Build tag: `integration_cognito`. Talks to a real AWS Cognito user pool via `pkg/migration/cognito`. Skips silently when the env file is absent so CI / dev workflows aren't broken.

**Setup**:

1. Copy the template:
   ```bash
   cp tests/.env.test.cognito.example tests/.env.test.cognito
   ```
2. Fill in `COGNITO_REGION`, `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID`. If the app client has a secret, also set `COGNITO_CLIENT_SECRET`.
3. Set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` either in this file or via the standard AWS credential chain (`~/.aws/credentials`).
4. Optionally set `COGNITO_TEST_PASSWORD` to enable the successful-login tests. Without it, those tests skip and only the negative paths run.

The `.env.test.cognito` file is gitignored — never commit real credentials.

**What the tests cover**:

| Test | Requires | Behavior |
|---|---|---|
| `TestCognitoAdapter_UnknownEmail` | pool + client | Email not in pool → `ErrLegacyUserNotFound` OR `ErrLegacyLoginFailed` (Cognito's `PreventUserExistenceErrors` setting collapses these). |
| `TestCognitoAdapter_WrongPassword` | + `COGNITO_TEST_SELLER_EMAIL` | Existing user, wrong password → `ErrLegacyLoginFailed`. |
| `TestCognitoAdapter_SuccessfulLogin_Seller` | + `COGNITO_TEST_PASSWORD` | Real login → adapter returns populated `LegacyUser` with email + name + groups. Skips when password not set. |
| `TestCognitoAdapter_DefaultRoleMapper_AppliesToRoles` | nothing | Pure unit test of role mapping; runs even without Cognito creds. |

**Cognito `PreventUserExistenceErrors`**: Cognito's app clients have a "Prevent user existence errors" setting (default `Enabled` for new pools). When enabled, Cognito returns `NotAuthorizedException` for both "user not found" and "wrong password" so attackers can't enumerate accounts. The adapter and tests accept both error shapes.

## Running everything locally

```bash
# Fast: unit tests only.
go test ./internal/... ./pkg/...

# Integration suite (needs Docker).
make test-integration

# Cognito migration (needs tests/.env.test.cognito).
go test -tags integration_cognito ./tests/specs/...

# All of the above:
go test ./internal/... ./pkg/... && \
  make test-integration && \
  go test -tags integration_cognito ./tests/specs/...
```
