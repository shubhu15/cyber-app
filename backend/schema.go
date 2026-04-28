package main

import (
	"context"
	"database/sql"
)

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
			top_src_ips_json JSONB NOT NULL,
			top_dst_ports_json JSONB NOT NULL,
			top_rejected_src_ips_json JSONB NOT NULL,
			timeline_json JSONB NOT NULL,
			ai_summary TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'sessions' AND column_name = 'session_hash'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'sessions' AND column_name = 'token_hash'
			) THEN
				ALTER TABLE sessions RENAME COLUMN session_hash TO token_hash;
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'uploads' AND column_name = 'original_filename'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'uploads' AND column_name = 'file_name'
			) THEN
				ALTER TABLE uploads RENAME COLUMN original_filename TO file_name;
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'uploads' AND column_name = 'completed_at'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'uploads' AND column_name = 'finished_at'
			) THEN
				ALTER TABLE uploads RENAME COLUMN completed_at TO finished_at;
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'uploads' AND column_name = 'total_lines'
			) THEN
				ALTER TABLE uploads ADD COLUMN total_lines INTEGER NOT NULL DEFAULT 0;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'uploads' AND column_name = 'parsed_lines'
			) THEN
				ALTER TABLE uploads ADD COLUMN parsed_lines INTEGER NOT NULL DEFAULT 0;
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'findings' AND column_name = 'event_count'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'findings' AND column_name = 'count'
			) THEN
				ALTER TABLE findings RENAME COLUMN event_count TO count;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'findings' AND column_name = 'first_seen_at'
			) THEN
				ALTER TABLE findings ADD COLUMN first_seen_at TIMESTAMPTZ NULL;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'findings' AND column_name = 'last_seen_at'
			) THEN
				ALTER TABLE findings ADD COLUMN last_seen_at TIMESTAMPTZ NULL;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'findings' AND column_name = 'metadata_json'
			) THEN
				ALTER TABLE findings ADD COLUMN metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb;
			END IF;
		END $$`,
		`DO $$
		BEGIN
			IF EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'total_events'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'total_records'
			) THEN
				ALTER TABLE summaries RENAME COLUMN total_events TO total_records;
			END IF;
			IF EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'summary_text'
			) AND NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'ai_summary'
			) THEN
				ALTER TABLE summaries RENAME COLUMN summary_text TO ai_summary;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'accepted_count'
			) THEN
				ALTER TABLE summaries ADD COLUMN accepted_count INTEGER NOT NULL DEFAULT 0;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'rejected_count'
			) THEN
				ALTER TABLE summaries ADD COLUMN rejected_count INTEGER NOT NULL DEFAULT 0;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'top_src_ips_json'
			) THEN
				ALTER TABLE summaries ADD COLUMN top_src_ips_json JSONB NOT NULL DEFAULT '[]'::jsonb;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'top_dst_ports_json'
			) THEN
				ALTER TABLE summaries ADD COLUMN top_dst_ports_json JSONB NOT NULL DEFAULT '[]'::jsonb;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'top_rejected_src_ips_json'
			) THEN
				ALTER TABLE summaries ADD COLUMN top_rejected_src_ips_json JSONB NOT NULL DEFAULT '[]'::jsonb;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'timeline_json'
			) THEN
				ALTER TABLE summaries ADD COLUMN timeline_json JSONB NOT NULL DEFAULT '[]'::jsonb;
			END IF;
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'summaries' AND column_name = 'ai_summary'
			) THEN
				ALTER TABLE summaries ADD COLUMN ai_summary TEXT NOT NULL DEFAULT '';
			END IF;
		END $$`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_uploads_user_created_at ON uploads(user_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_uploads_status_created_at ON uploads(status, created_at ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_event_logs_upload_start_time ON event_logs(upload_id, start_time ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_upload_created_at ON findings(upload_id, created_at ASC)`,
	}

	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}

	return nil
}
