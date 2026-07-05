#!/bin/sh
set -e

echo "VEN Auth Server - Starting..."

DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_NAME="${DB_NAME:-auth}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"

# Wait for PostgreSQL
echo "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
MAX_ATTEMPTS=30
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" > /dev/null 2>&1; then
        echo "PostgreSQL is ready."
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    echo "PostgreSQL is not ready (attempt ${ATTEMPT}/${MAX_ATTEMPTS}) - waiting..."
    sleep 2
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    echo "ERROR: PostgreSQL did not become ready in time. Exiting."
    exit 1
fi

# Verify we can actually connect to the database
echo "Verifying database connection..."
ATTEMPT=0
while [ $ATTEMPT -lt 10 ]; do
    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" > /dev/null 2>&1; then
        echo "Database '${DB_NAME}' is accessible."
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    echo "Database not yet accessible (attempt ${ATTEMPT}/10) - waiting..."
    sleep 2
done

if [ $ATTEMPT -eq 10 ]; then
    echo "WARNING: Could not verify database '${DB_NAME}' - continuing anyway."
fi

# Check Redis availability (non-blocking)
REDIS_HOST="${REDIS_HOST:-redis}"
REDIS_PORT="${REDIS_PORT:-6379}"
echo "Checking Redis at ${REDIS_HOST}:${REDIS_PORT}..."
REDIS_READY=false
REDIS_ATTEMPTS=0
REDIS_MAX_ATTEMPTS=5

while [ $REDIS_ATTEMPTS -lt $REDIS_MAX_ATTEMPTS ]; do
    if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping 2>/dev/null | grep -q PONG; then
        REDIS_READY=true
        break
    fi
    REDIS_ATTEMPTS=$((REDIS_ATTEMPTS + 1))
    sleep 1
done

if [ "$REDIS_READY" = "true" ]; then
    echo "Redis is ready."
else
    echo "Warning: Redis is not available. Running without Redis cache."
fi

# Run migrations if enabled
if [ "${RUN_MIGRATIONS}" = "true" ]; then
    echo "Running database migrations..."
    for migration in /app/migrations/*.sql; do
        if [ -f "$migration" ]; then
            echo "Applying: $(basename "$migration")"
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$migration" 2>&1 || true
        fi
    done
    echo "Migrations complete."
fi

echo "Starting auth server..."
exec "$@"
