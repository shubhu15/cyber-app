package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

type claimedUpload struct {
	ID       int64
	UserID   int64
	LogType  string
	FileName string
	FileRef  string
}

func (app *application) runWorker(ctx context.Context) error {
	ticker := time.NewTicker(app.config.WorkerPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		processed, err := app.processNextUpload(ctx)
		if err != nil {
			log.Printf("worker error: %v", err)
		}

		if processed {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (app *application) processNextUpload(ctx context.Context) (bool, error) {
	upload, ok, err := app.claimNextUpload(ctx)
	if err != nil || !ok {
		return ok, err
	}

	if err := app.processUpload(ctx, upload); err != nil {
		if markErr := app.markUploadFailed(ctx, upload.ID, err.Error()); markErr != nil {
			return true, fmt.Errorf("process upload: %v; mark failed: %w", err, markErr)
		}
		return true, err
	}

	return true, nil
}

func (app *application) claimNextUpload(ctx context.Context) (*claimedUpload, bool, error) {
	tx, err := app.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `
		SELECT id, user_id, log_type, file_name, file_ref
		FROM uploads
		WHERE status = 'pending' AND log_type = $1
		ORDER BY created_at ASC
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`, logTypeVPC)

	upload := &claimedUpload{}
	if err := row.Scan(&upload.ID, &upload.UserID, &upload.LogType, &upload.FileName, &upload.FileRef); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE uploads
		SET status = 'processing', started_at = NOW(), finished_at = NULL, error_message = NULL, total_lines = 0, parsed_lines = 0
		WHERE id = $1
	`, upload.ID); err != nil {
		return nil, false, err
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}

	return upload, true, nil
}

func (app *application) processUpload(ctx context.Context, upload *claimedUpload) error {
	if err := app.clearUploadArtifacts(ctx, upload.ID); err != nil {
		return err
	}

	totalLines, err := app.countTotalLines(upload.FileRef)
	if err != nil {
		return err
	}
	if _, err := app.db.ExecContext(ctx, `
		UPDATE uploads
		SET total_lines = $2
		WHERE id = $1
	`, upload.ID, totalLines); err != nil {
		return err
	}

	file, err := app.storage.Open(upload.FileRef)
	if err != nil {
		return err
	}
	defer file.Close()

	acc := newAnalysisAccumulator()
	agg := newFindingsAggregator()
	pendingEvents := make([]processedEvent, 0, 1000)
	reader := bufio.NewScanner(file)
	reader.Buffer(make([]byte, 0, 1024), 1024*1024)

	flush := func() error {
		if len(pendingEvents) == 0 {
			return nil
		}
		if err := app.insertEventLogsBatch(ctx, pendingEvents); err != nil {
			return err
		}
		if err := app.updateUploadProgress(ctx, upload.ID, acc.parsedLines); err != nil {
			return err
		}
		pendingEvents = pendingEvents[:0]
		return nil
	}

	for reader.Scan() {
		acc.addLine()
		trimmed := strings.TrimSpace(reader.Text())
		if trimmed == "" {
			continue
		}

		parsed, ok := parseVpcFlowLine(trimmed)
		if !ok {
			acc.addParseError()
			continue
		}

		acc.addEvent(parsed)
		agg.add(parsed)
		pendingEvents = append(pendingEvents, processedEvent{
			UploadID:    upload.ID,
			Version:     parsed.Version,
			AccountID:   parsed.AccountID,
			InterfaceID: parsed.InterfaceID,
			SrcAddr:     parsed.SrcAddr,
			DstAddr:     parsed.DstAddr,
			SrcPort:     parsed.SrcPort,
			DstPort:     parsed.DstPort,
			Protocol:    parsed.Protocol,
			Packets:     parsed.Packets,
			Bytes:       parsed.Bytes,
			StartTime:   parsed.StartTime,
			EndTime:     parsed.EndTime,
			Action:      parsed.Action,
			LogStatus:   parsed.LogStatus,
			RawLine:     trimmed,
		})

		if len(pendingEvents) >= 1000 {
			if err := flush(); err != nil {
				return err
			}
		}
	}

	if err := reader.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	if err := flush(); err != nil {
		return err
	}

	findings := agg.build()
	timelineEntries := agg.timeline()
	if timelineEntries == nil {
		timelineEntries = []timelineEntry{}
	}

	topSrcJSON := toJSON(toChartPoints(topCountPairs(acc.srcCounts, 10)))
	topDstPortsJSON := toJSON(toChartPoints(topCountPairs(acc.dstPortCounts, 10)))
	topRejectedSrcJSON := toJSON(toChartPoints(topCountPairs(acc.rejectedSrcCounts, 10)))
	timelineJSON := toJSON(timelineEntries)
	aiSummary := buildAISummary(acc, findings)

	tx, err := app.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, finding := range findings {
		metadataJSON, err := json.Marshal(finding.Metadata)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO findings (
				upload_id, type, severity, title, description, first_seen_at, last_seen_at, count, metadata_json
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
		`, upload.ID, finding.Type, finding.Severity, finding.Title, finding.Description, finding.FirstSeenAt, finding.LastSeenAt, finding.Count, string(metadataJSON)); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO summaries (
			upload_id, total_records, accepted_count, rejected_count, parse_errors,
			top_src_ips_json, top_dst_ports_json, top_rejected_src_ips_json, timeline_json, ai_summary, created_at
		) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10, NOW())
	`, upload.ID, acc.parsedLines, acc.acceptedCount, acc.rejectedCount, acc.parseErrors, topSrcJSON, topDstPortsJSON, topRejectedSrcJSON, timelineJSON, aiSummary); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE uploads
		SET status = 'completed', total_lines = $2, parsed_lines = $3, finished_at = NOW(), error_message = NULL
		WHERE id = $1
	`, upload.ID, acc.totalLines, acc.parsedLines); err != nil {
		return err
	}

	return tx.Commit()
}

func (app *application) clearUploadArtifacts(ctx context.Context, uploadID int64) error {
	tx, err := app.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	statements := []string{
		`DELETE FROM event_logs WHERE upload_id = $1`,
		`DELETE FROM findings WHERE upload_id = $1`,
		`DELETE FROM summaries WHERE upload_id = $1`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement, uploadID); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (app *application) countTotalLines(fileRef string) (int, error) {
	file, err := app.storage.Open(fileRef)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	reader := bufio.NewScanner(file)
	reader.Buffer(make([]byte, 0, 1024), 1024*1024)
	totalLines := 0
	for reader.Scan() {
		totalLines++
	}
	if err := reader.Err(); err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	return totalLines, nil
}

func (app *application) updateUploadProgress(ctx context.Context, uploadID int64, parsedLines int) error {
	_, err := app.db.ExecContext(ctx, `
		UPDATE uploads
		SET parsed_lines = $2
		WHERE id = $1 AND status = 'processing'
	`, uploadID, parsedLines)
	return err
}

func (app *application) insertEventLogsBatch(ctx context.Context, events []processedEvent) error {
	if len(events) == 0 {
		return nil
	}

	var builder strings.Builder
	builder.WriteString(`
		INSERT INTO event_logs (
			upload_id, version, account_id, interface_id, src_addr, dst_addr, src_port, dst_port,
			protocol, packets, bytes, start_time, end_time, action, log_status, raw_line
		) VALUES
	`)

	args := make([]any, 0, len(events)*16)
	placeholder := 1
	for index, event := range events {
		if index > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			placeholder, placeholder+1, placeholder+2, placeholder+3, placeholder+4, placeholder+5, placeholder+6, placeholder+7,
			placeholder+8, placeholder+9, placeholder+10, placeholder+11, placeholder+12, placeholder+13, placeholder+14, placeholder+15,
		))
		args = append(args,
			event.UploadID,
			event.Version,
			nullableString(event.AccountID),
			nullableString(event.InterfaceID),
			nullableString(event.SrcAddr),
			nullableString(event.DstAddr),
			nullableInt(event.SrcPort),
			nullableInt(event.DstPort),
			nullableInt(event.Protocol),
			nullableInt64(event.Packets),
			nullableInt64(event.Bytes),
			nullableTime(event.StartTime),
			nullableTime(event.EndTime),
			nullableString(event.Action),
			event.LogStatus,
			event.RawLine,
		)
		placeholder += 16
	}

	_, err := app.db.ExecContext(ctx, builder.String(), args...)
	return err
}

func (app *application) markUploadFailed(ctx context.Context, uploadID int64, message string) error {
	_, err := app.db.ExecContext(ctx, `
		UPDATE uploads
		SET status = 'failed', error_message = $2, finished_at = NOW()
		WHERE id = $1
	`, uploadID, truncate(message, 500))
	return err
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}
