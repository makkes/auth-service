package postgres

import (
	"database/sql"
	"time"

	"github.com/lib/pq"

	"golang.org/x/xerrors"
)

const (
	sqlMigrationsTableCreation = `CREATE TABLE migrations(
		id INTEGER PRIMARY KEY NOT NULL,
		applied TIMESTAMP WITH TIME ZONE NOT NULL
	)`
)

var (
	migrations = []string{
		`CREATE TABLE apps(
			id VARCHAR(256) PRIMARY KEY NOT NULL,
			name VARCHAR(256) NOT NULL,
			max_accounts integer NOT NULL,
			allowed_origin varchar(1024) NOT NULL,
			mail_templates varchar(100000) NOT NULL,
			admins varchar(4096) NOT NULL,
			private_key varchar(4096) NOT NULL
		)`,
		`CREATE TABLE accounts(
			id UUID NOT NULL,
			app_id VARCHAR(256) NOT NULL,
			email varchar(256) NOT NULL,
			roles varchar(100000) NOT NULL,
			pw_hash varchar(1024) NOT NULL,
			active boolean NOT NULL,
			PRIMARY KEY (id, app_id),
			FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE activation_tokens(
			app_id VARCHAR(256) NOT NULL,
			account_id UUID NOT NULL,
			token VARCHAR(256) NOT NULL
		)`,
	}
)

type migration struct {
	ID      int
	Applied time.Time
}

func migrate(db *sql.DB) error {
	latestMigrationIndex := -1
	var latestMigration migration
	err := db.QueryRow("SELECT * FROM migrations ORDER BY id DESC LIMIT 1").Scan(&(latestMigration.ID), &(latestMigration.Applied))
	if err != nil {
		if pqError, ok := err.(*pq.Error); ok && pqError.Code == "42P01" {
			creationErr := createMigrationsTable(db)
			if creationErr != nil {
				return xerrors.Errorf("could not create migrations table: %w", creationErr)
			}
		} else if err != sql.ErrNoRows {
			return xerrors.Errorf("querying migrations failed: %w", err)
		}
	} else {
		latestMigrationIndex = latestMigration.ID
	}
	for idx, migration := range migrations[latestMigrationIndex+1:] {
		idx += latestMigrationIndex + 1
		_, err = db.Exec(migration)
		if err != nil {
			return xerrors.Errorf("could not apply migration %d: %w", idx, err)
		}
		_, err := db.Exec("INSERT INTO migrations(id, applied) VALUES($1, $2)", idx, time.Now())
		if err != nil {
			return xerrors.Errorf("could not increment migration to %d: %w", idx, err)
		}
	}

	return nil
}

func createMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(sqlMigrationsTableCreation)
	if err != nil {
		return err
	}
	return nil
}