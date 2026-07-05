#!/bin/bash
# Migration runner for the auth server
# Usage: ./scripts/migrate.sh [up|status|reset]
#
# Reads DB connection from .env or environment variables.
# Migrations are in ./migrations/ as numbered SQL files (NNN_name.up.sql).

set -e

# Load .env if it exists (filter out comments to avoid bash interpretation errors)
if [ -f .env ]; then
    while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        export "$line" 2>/dev/null || true
    done < .env
fi

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"
DB_NAME="${DB_NAME:-auth}"
MIGRATIONS_DIR="./migrations"

export PGPASSWORD="$DB_PASSWORD"
PSQL="psql -U $DB_USER -h $DB_HOST -p $DB_PORT -d $DB_NAME -v ON_ERROR_STOP=1"

# Create tracking table if it doesn't exist
$PSQL -c "
CREATE TABLE IF NOT EXISTS _migrations (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL UNIQUE,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
" 2>/dev/null

case "${1:-up}" in
    up)
        echo "Running migrations on $DB_NAME..."
        applied=0
        for f in $(ls "$MIGRATIONS_DIR"/*.up.sql 2>/dev/null | sort); do
            fname=$(basename "$f")
            # Check if already applied
            already=$($PSQL -t -c "SELECT COUNT(*) FROM _migrations WHERE filename = '$fname'" 2>/dev/null | tr -d ' ')
            if [ "$already" = "0" ]; then
                echo "  Applying: $fname"
                # Apply the file AND the tracker insert in a single
                # psql transaction (--single-transaction wraps every
                # -f / -c in one BEGIN/COMMIT). If anything in the
                # migration fails, NEITHER the DDL/DML NOR the
                # tracker row gets committed — schema and _migrations
                # stay in lockstep. Mirrors the Go boot-time
                # migrator's contract in
                # internal/repository/postgres/migrator.go.
                psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" \
                     -v ON_ERROR_STOP=1 \
                     --single-transaction \
                     -f "$f" \
                     -c "INSERT INTO _migrations (filename) VALUES ('$fname')"
                applied=$((applied + 1))
            fi
        done
        if [ "$applied" = "0" ]; then
            echo "  All migrations already applied."
        else
            echo "  Applied $applied migration(s)."
        fi
        ;;

    status)
        echo "Migration status for $DB_NAME:"
        echo ""
        for f in $(ls "$MIGRATIONS_DIR"/*.up.sql 2>/dev/null | sort); do
            fname=$(basename "$f")
            applied=$($PSQL -t -c "SELECT applied_at FROM _migrations WHERE filename = '$fname'" 2>/dev/null | tr -d ' ')
            if [ -n "$applied" ]; then
                echo "  ✓ $fname  (applied: $applied)"
            else
                echo "  ○ $fname  (pending)"
            fi
        done
        ;;

    reset)
        echo "⚠️  Resetting database $DB_NAME (dropping and recreating)..."
        read -p "Are you sure? [y/N] " confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"
            PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d postgres -c "CREATE DATABASE $DB_NAME;"
            echo "  Database recreated. Running all migrations..."
            exec "$0" up
        else
            echo "  Cancelled."
        fi
        ;;

    *)
        echo "Usage: $0 [up|status|reset]"
        echo "  up     — Apply pending migrations (default)"
        echo "  status — Show migration status"
        echo "  reset  — Drop and recreate database, re-run all migrations"
        exit 1
        ;;
esac
