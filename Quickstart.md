- Ensure docker is running

make docker-up 		# Start docker auth, postgres, and redis servers

make docker-logs    # tail logs from all services
make docker-down    # stop containers
make docker-clean   # stop + delete volumes (fresh start)

# Run Integration Tests

The integration tests run against the Docker PostgreSQL and Redis but spin up their own Go HTTP test server (not the containerized one):

make test-integration

This script (scripts/run-tests.sh) will:
1. Ensure postgres and redis containers are running and healthy
2. Set env vars pointing to localhost:5432 / localhost:6379
3. Run go test ./tests/... -v -tags=integration
4. Clean up containers on exit

Alternative - if you want to keep the containers running between test runs (faster iteration):

# Start just the dependencies (skip auth-server container)
docker compose up -d postgres redis

# Wait for healthy
docker compose exec postgres pg_isready -U postgres -d auth

# Run tests manually
export DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=auth DB_SSL_MODE=disable
export REDIS_HOST=localhost REDIS_PORT=6379
export JWT_ACCESS_SECRET=dev-access-secret-key-change-in-production-minimum-32-chars
export JWT_REFRESH_SECRET=dev-refresh-secret-key-change-in-production-minimum-32-chars
export RATE_LIMIT_REQUESTS=1000 RATE_LIMIT_WINDOW=1m

go test ./tests/... -v -tags=integration -count=1

Verify Redis is Being Used

After a login via curl or the tests:

docker exec ven-auth-redis redis-cli keys "auth:*"

You should see keys like auth:token:... (cached validated tokens), auth:ratelimit:... (per-IP), auth:account_attempts:... (per-account), auth:user_tv:... (per-user token-version), auth:sso:state:... (SSO state), auth:idem:... (idempotency cache).

# Cognito migration tests (optional, hits real AWS)

cp tests/.env.test.cognito.example tests/.env.test.cognito
# Fill in COGNITO_REGION / COGNITO_USER_POOL_ID / COGNITO_CLIENT_ID etc.
go test -tags integration_cognito ./tests/specs/...

Tests skip silently when the env file is absent. See tests/README.md.