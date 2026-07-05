package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Migrator applies any unapplied .up.sql files in `dir`. Tracks applied
// filenames in `_migrations` (same shape as scripts/migrate.sh) so a
// fresh deploy doesn't re-run history and an upgrade picks up only the
// new tail.
//
// Why in-process: deploy workflows kept skipping the migrate step (we
// shipped 013 without applying it on prod). Boot-time migration removes
// the "did someone run psql?" coordination — the server can't start
// against a stale schema because it does the apply itself.
//
// Safety:
//   - Each .up.sql runs inside a transaction. A partial migration rolls
//     back; the row in _migrations is only inserted after a successful
//     commit. Subsequent restarts re-attempt the same file.
//   - Migration files are sorted lexicographically (matches the
//     `NNN_name.up.sql` numbering convention). A file inserted out of
//     order with a low number would be applied after later ones — by
//     convention we never backfill, only append.
//   - If `dir` doesn't exist or is empty, Run is a no-op.
type Migrator struct {
	db  *DB
	dir string
	log *slog.Logger
}

// NewMigrator wires the migrator with the shared sqlx handle and the
// directory containing migration files.
func NewMigrator(db *DB, dir string, log *slog.Logger) *Migrator {
	if log == nil {
		log = slog.Default()
	}
	return &Migrator{db: db, dir: dir, log: log}
}

// Run applies every unapplied .up.sql file in `dir`. Idempotent: a
// second call on an up-to-date DB is a no-op.
func (m *Migrator) Run(ctx context.Context) error {
	if _, err := os.Stat(m.dir); os.IsNotExist(err) {
		m.log.Info("migrations: directory not present — skipping", "dir", m.dir)
		return nil
	}

	if err := m.ensureTrackerTable(ctx); err != nil {
		return fmt.Errorf("migrations: create _migrations table: %w", err)
	}

	applied, err := m.appliedSet(ctx)
	if err != nil {
		return fmt.Errorf("migrations: read applied set: %w", err)
	}

	files, err := m.listMigrationFiles()
	if err != nil {
		return fmt.Errorf("migrations: list dir %q: %w", m.dir, err)
	}

	var pending []string
	for _, f := range files {
		if !applied[f] {
			pending = append(pending, f)
		}
	}
	if len(pending) == 0 {
		m.log.Info("migrations: schema up to date", "applied", len(applied))
		return nil
	}

	m.log.Info("migrations: applying pending", "count", len(pending))
	for _, f := range pending {
		if err := m.applyOne(ctx, f); err != nil {
			return fmt.Errorf("migrations: apply %s: %w", f, err)
		}
		m.log.Info("migrations: applied", "file", f)
	}
	return nil
}

func (m *Migrator) ensureTrackerTable(ctx context.Context) error {
	const q = `
		CREATE TABLE IF NOT EXISTS _migrations (
			id          SERIAL PRIMARY KEY,
			filename    VARCHAR(255) NOT NULL UNIQUE,
			applied_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`
	_, err := m.db.ExecContext(ctx, q)
	return err
}

func (m *Migrator) appliedSet(ctx context.Context) (map[string]bool, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT filename FROM _migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var fname string
		if err := rows.Scan(&fname); err != nil {
			return nil, err
		}
		out[fname] = true
	}
	return out, rows.Err()
}

func (m *Migrator) listMigrationFiles() ([]string, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Only apply .up.sql; .down.sql files are operator-only.
		if strings.HasSuffix(name, ".up.sql") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// applyOne reads and executes the file body inside a transaction, then
// records it in _migrations. Failure rolls back both the migration and
// the tracker row — the same filename will be retried on next boot.
func (m *Migrator) applyOne(ctx context.Context, fname string) error {
	body, err := os.ReadFile(filepath.Join(m.dir, fname))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	tx, err := m.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		// Best-effort rollback. If commit succeeded the rollback is a
		// no-op; if it failed the rollback finalizes the transaction.
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO _migrations (filename) VALUES ($1)`, fname); err != nil {
		return fmt.Errorf("insert tracker row: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
