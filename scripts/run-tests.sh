#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== VEN Auth Server - Integration Tests ==="

# Start test dependencies
echo "Starting test dependencies..."
docker compose up -d postgres redis

# Wait for services to be healthy
echo "Waiting for PostgreSQL..."
until docker compose exec -T postgres pg_isready -U postgres -d auth -q 2>/dev/null; do
    sleep 2
done
echo "PostgreSQL is ready."

echo "Waiting for Redis..."
until docker compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do
    sleep 1
done
echo "Redis is ready."

# Set test environment variables
export DB_HOST=localhost
export DB_PORT=5433
export DB_USER=postgres
export DB_PASSWORD=postgres
export DB_NAME=auth
export DB_SSL_MODE=disable
export REDIS_HOST=localhost
export REDIS_PORT=6380
export JWT_ACCESS_SECRET=test-access-secret-key-for-integration-tests
export JWT_REFRESH_SECRET=test-refresh-secret-key-for-integration-tests
export JWT_ISSUER=ven-auth-test
export ENVIRONMENT=test
export SERVER_PORT=0
export RATE_LIMIT_REQUESTS=1000
export RATE_LIMIT_WINDOW=1m

# Run integration tests
echo ""
echo "Running integration tests..."
go test ./tests/specs/... -v -tags=integration -count=1 -timeout=120s
TEST_EXIT=$?

# Cleanup
cleanup() {
    echo ""
    echo "Cleaning up test dependencies..."
    docker compose down -v
}

trap cleanup EXIT

exit $TEST_EXIT
