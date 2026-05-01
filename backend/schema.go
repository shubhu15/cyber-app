package main

import (
	"context"
	"database/sql"
)

// schemaBootstrapLockKey is an arbitrary constant used with pg_advisory_xact_lock
// to serialize concurrent boots of the API and worker (which both call
// initializeDatabase). Without it, two processes can race on CREATE TABLE
// IF NOT EXISTS and one fails with a pg_class_relname_nsp_index unique-violation.
const schemaBootstrapLockKey int64 = 0x736c615f696e6974 // "sla_init"

// initializeDatabase is run on every API and worker boot. The CREATE TABLE
// statements are the single source of truth for the schema and must match
// what the rest of the package reads/writes. There is no separate migration
// system: a fresh DB is built from these statements alone.
func initializeDatabase(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL UNIQUE,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS uploads (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			file_name TEXT NOT NULL,
			log_type TEXT NOT NULL,
			storage_type TEXT NOT NULL,
			file_ref TEXT NOT NULL,
			status TEXT NOT NULL,
			error_message TEXT NULL,
			total_lines INTEGER NOT NULL DEFAULT 0,
			parsed_lines INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			started_at TIMESTAMPTZ NULL,
			finished_at TIMESTAMPTZ NULL
		)`,
		`CREATE TABLE IF NOT EXISTS event_logs (
			id BIGSERIAL PRIMARY KEY,
			upload_id BIGINT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
			version INTEGER NOT NULL,
			account_id TEXT NULL,
			interface_id TEXT NULL,
			src_addr TEXT NULL,
			dst_addr TEXT NULL,
			src_port INTEGER NULL,
			dst_port INTEGER NULL,
			protocol INTEGER NULL,
			packets BIGINT NULL,
			bytes BIGINT NULL,
			start_time TIMESTAMPTZ NULL,
			end_time TIMESTAMPTZ NULL,
			action TEXT NULL,
			log_status TEXT NOT NULL,
			raw_line TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id BIGSERIAL PRIMARY KEY,
			upload_id BIGINT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
			type TEXT NOT NULL,
			severity TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			first_seen_at TIMESTAMPTZ NULL,
			last_seen_at TIMESTAMPTZ NULL,
			count INTEGER NOT NULL,
			metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS summaries (
			id BIGSERIAL PRIMARY KEY,
			upload_id BIGINT NOT NULL UNIQUE REFERENCES uploads(id) ON DELETE CASCADE,
			total_records INTEGER NOT NULL,
			accepted_count INTEGER NOT NULL,
			rejected_count INTEGER NOT NULL,
			parse_errors INTEGER NOT NULL,
			nodata_count INTEGER NOT NULL DEFAULT 0,
			skipdata_count INTEGER NOT NULL DEFAULT 0,
			charts_json JSONB NOT NULL DEFAULT '{}'::jsonb,
			timeline_json JSONB NOT NULL DEFAULT '[]'::jsonb,
			ai_summary TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ai_analyses (
			id BIGSERIAL PRIMARY KEY,
			upload_id BIGINT NOT NULL UNIQUE REFERENCES uploads(id) ON DELETE CASCADE,
			model TEXT NOT NULL,
			report_json JSONB NOT NULL,
			payload_hash TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		`CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_uploads_user_created_at ON uploads(user_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_uploads_status_created_at ON uploads(status, created_at ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_event_logs_upload_start_time ON event_logs(upload_id, start_time ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_upload_created_at ON findings(upload_id, created_at ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_ai_analyses_upload_id ON ai_analyses(upload_id)`,
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", schemaBootstrapLockKey); err != nil {
		return err
	}

	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}

	return tx.Commit()
}
