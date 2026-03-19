// Package database provides database utilities including embedded migrations.
package database

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	"github.com/highflame-ai/zeroid/migrations"
)

// RunMigrations executes all pending database migrations using the embedded SQL files.
func RunMigrations(db *bun.DB) error {
	log.Info().Msg("Running database migrations...")

	sqlDB := db.DB

	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create postgres driver: %w", err)
	}

	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("failed to create iofs source: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// m.Version returns ErrNilVersion when no migrations have run yet; treat that as version 0.
	version, dirty, _ := m.Version()
	log.Info().Uint("current_version", version).Bool("dirty", dirty).Msg("Current migration state")

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Info().Msg("No new migrations to apply")
			return nil
		}
		return fmt.Errorf("migration failed: %w", err)
	}

	// dirty and error are ignored here: if Up() succeeded the state is clean by definition.
	newVersion, _, _ := m.Version()
	log.Info().
		Uint("from_version", version).
		Uint("to_version", newVersion).
		Msg("Migrations completed successfully")

	return nil
}
