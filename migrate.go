package zeroid

import (
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
//	zeroid.Migrate("postgres://user:pass@host:5432/zeroid?sslmode=disable")
func Migrate(databaseURL string) error {
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(databaseURL)))
	db := bun.NewDB(sqldb, pgdialect.New())
	defer db.Close()

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
