package zeroid

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/highflame-ai/zeroid/internal/database"
	"github.com/highflame-ai/zeroid/migrations"
)

// Migrate runs all pending ZeroID schema migrations against the given database URL.
// This is the recommended way to apply migrations in production — call it from a
// CI/CD step, init container, or CLI command before starting the server with
// AutoMigrate: false.
//
// Migrate tolerates a transient cross-service startup race: if postgres is
// briefly unreachable (e.g., the DB pod is still binding 5432 while authn
// boots in parallel), Migrate retries the connection with bounded
// exponential backoff for up to 60 seconds before giving up.
//
//	zeroid.Migrate("postgres://user:pass@host:5432/zeroid?sslmode=disable")
func Migrate(databaseURL string) error {
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(databaseURL)))
	db := bun.NewDB(sqldb, pgdialect.New())
	defer func() { _ = db.Close() }()

	// Wait for postgres to actually accept connections before we let
	// golang-migrate's WithInstance try (it Pings internally and treats
	// any error as fatal — no retries).
	if err := database.WaitForReachable(context.Background(), sqldb, database.WaitOptions{}); err != nil {
		return fmt.Errorf("zeroid migration: %w", err)
	}

	if err := database.RunMigrations(db); err != nil {
		return fmt.Errorf("zeroid migration failed: %w", err)
	}
	return nil
}

// MigrationFiles returns the embedded filesystem containing ZeroID's SQL migration files.
// Use this when you want to integrate ZeroID's migrations into your own migration
// toolchain (e.g., golang-migrate, atlas, goose) rather than using Migrate().
//
//	migrationFS := zeroid.MigrationFiles()
//	// Pass to your migration tool...
func MigrationFiles() fs.FS {
	return migrations.FS
}
