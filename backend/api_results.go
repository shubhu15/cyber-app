package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

func (app *application) handleUploadResults(w http.ResponseWriter, r *http.Request, uploadID int64) {
	user := sessionUserFromContext(r.Context())
	status, found, err := app.fetchUploadStatus(r.Context(), user.ID, uploadID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read upload results."})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, messageResponse{Message: "Upload not found."})
		return
	}
	if status.Status != "completed" {
		writeJSON(w, http.StatusConflict, messageResponse{Message: "Upload is not completed yet."})
		return
	}

	summary, timeline, charts, err := app.fetchSummary(r.Context(), uploadID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read upload summary."})
		return
	}
	summary.TotalLines = status.TotalLines
	summary.ParsedPercent = computeParsedPercent(status.TotalLines, summary.TotalRecords)
	findings, err := app.fetchFindings(r.Context(), uploadID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read findings."})
		return
	}

	writeJSON(w, http.StatusOK, resultsResponse{
		Upload:   status,
		Summary:  summary,
		Findings: findings,
		Timeline: timeline,
		Charts:   charts,
	})
}

func (app *application) handleUploadAIAnalysis(w http.ResponseWriter, r *http.Request, uploadID int64) {
	user := sessionUserFromContext(r.Context())
	status, found, err := app.fetchUploadStatus(r.Context(), user.ID, uploadID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read upload status."})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, messageResponse{Message: "Upload not found."})
		return
	}
	if status.Status != "completed" {
		writeJSON(w, http.StatusConflict, messageResponse{Message: "Upload is not completed yet."})
		return
	}

	summary, timeline, charts, err := app.fetchSummary(r.Context(), uploadID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read upload summary."})
		return
	}
	summary.TotalLines = status.TotalLines
	summary.ParsedPercent = computeParsedPercent(status.TotalLines, summary.TotalRecords)

	findings, err := app.fetchFindings(r.Context(), uploadID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read findings."})
		return
	}

	payloadJSON, payloadHash, err := buildAIAnalysisPayload(status, summary, findings, timeline, charts)
	if err != nil {
		log.Printf("ai analysis payload error: upload_id=%d user_id=%d err=%v", uploadID, user.ID, err)
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to prepare AI analysis payload."})
		return
	}

	model := selectedAIModel(app.config)
	store := dbAIAnalysisStore{db: app.db}
	log.Printf("ai analysis request: upload_id=%d user_id=%d model=%s payload_hash=%s payload_bytes=%d", uploadID, user.ID, model, payloadHash, len(payloadJSON))
	report, err := getOrCreateAIAnalysis(
		r.Context(),
		store,
		func() (aiAnalysisClient, error) {
			return newClaudeClient(app.config)
		},
		uploadID,
		payloadHash,
		payloadJSON,
		model,
		time.Now(),
	)
	if err != nil {
		if errors.Is(err, errMissingAIAPIKey) {
			log.Printf("ai analysis config error: upload_id=%d user_id=%d err=%v", uploadID, user.ID, err)
			writeJSON(w, http.StatusServiceUnavailable, messageResponse{Message: "AI provider API key is not configured."})
			return
		}
		log.Printf("ai analysis generation error: upload_id=%d user_id=%d model=%s err=%v", uploadID, user.ID, model, err)
		writeJSON(w, http.StatusBadGateway, messageResponse{Message: "Unable to generate AI analysis. Check the API terminal logs for details."})
		return
	}

	log.Printf("ai analysis success: upload_id=%d user_id=%d model=%s", uploadID, user.ID, report.Model)
	writeJSON(w, http.StatusOK, report)
}

func (app *application) fetchSummary(ctx context.Context, uploadID int64) (summaryPayload, []timelineEntry, chartData, error) {
	row := app.db.QueryRowContext(ctx, `
		SELECT total_records, accepted_count, rejected_count, parse_errors,
		       nodata_count, skipdata_count,
		       charts_json, timeline_json, ai_summary
		FROM summaries
		WHERE upload_id = $1
	`, uploadID)

	var payload summaryPayload
	var chartsJSON string
	var timelineJSON string
	if err := row.Scan(
		&payload.TotalRecords,
		&payload.AcceptedCount,
		&payload.RejectedCount,
		&payload.ParseErrors,
		&payload.NoDataCount,
		&payload.SkipDataCount,
		&chartsJSON,
		&timelineJSON,
		&payload.AISummary,
	); err != nil {
		return summaryPayload{}, nil, chartData{}, err
	}

	var timeline []timelineEntry
	if err := json.Unmarshal([]byte(timelineJSON), &timeline); err != nil {
		return summaryPayload{}, nil, chartData{}, err
	}
	if timeline == nil {
		timeline = []timelineEntry{}
	}

	var charts chartData
	if strings.TrimSpace(chartsJSON) != "" {
		if err := json.Unmarshal([]byte(chartsJSON), &charts); err != nil {
			return summaryPayload{}, nil, chartData{}, err
		}
	}
	charts.TopSrcIPs = ensureChartPoints(charts.TopSrcIPs)
	charts.TopDstPorts = ensureChartPoints(charts.TopDstPorts)
	charts.TopRejectedSrcIPs = ensureChartPoints(charts.TopRejectedSrcIPs)
	charts.TopInterfaces = ensureChartPoints(charts.TopInterfaces)
	charts.TopTalkersByBytes = ensureChartPoints(charts.TopTalkersByBytes)
	if charts.TopConversations == nil {
		charts.TopConversations = []conversation{}
	}
	if charts.InternalExternal == nil {
		charts.InternalExternal = []internalExternalBucket{}
	}
	if charts.BurstWindows == nil {
		charts.BurstWindows = []burstWindow{}
	}

	return payload, timeline, charts, nil
}

func ensureChartPoints(points []chartPoint) []chartPoint {
	if points == nil {
		return []chartPoint{}
	}
	return points
}

func (app *application) fetchFindings(ctx context.Context, uploadID int64) ([]severityBucket, error) {
	rows, err := app.db.QueryContext(ctx, `
		SELECT type, severity, title, description, first_seen_at, last_seen_at, count, metadata_json
		FROM findings
		WHERE upload_id = $1
		  AND type IN ($2, $3, $4, $5, $6)
		ORDER BY count DESC, created_at ASC
	`, uploadID, findingRejectedTraffic, findingHighPortScan, findingSensitivePort, findingSSHBruteForce, findingSuspiciousProbe)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type groupKey struct {
		severity string
		typeKey  string
	}
	groups := make(map[groupKey]*findingGroup)
	groupOrder := make([]groupKey, 0)

	for rows.Next() {
		var (
			typeValue    string
			severity     string
			title        string
			description  string
			firstSeen    sql.NullTime
			lastSeen     sql.NullTime
			count        int
			metadataJSON string
		)
		if err := rows.Scan(&typeValue, &severity, &title, &description, &firstSeen, &lastSeen, &count, &metadataJSON); err != nil {
			return nil, err
		}

		instance := findingInstance{
			Description: description,
			Count:       count,
			Metadata:    map[string]any{},
		}
		if firstSeen.Valid {
			value := firstSeen.Time.UTC().Format(time.RFC3339)
			instance.FirstSeenAt = &value
		}
		if lastSeen.Valid {
			value := lastSeen.Time.UTC().Format(time.RFC3339)
			instance.LastSeenAt = &value
		}
		if strings.TrimSpace(metadataJSON) != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &instance.Metadata); err != nil {
				return nil, err
			}
			if instance.Metadata == nil {
				instance.Metadata = map[string]any{}
			}
		}

		key := groupKey{severity: severity, typeKey: typeValue}
		group, exists := groups[key]
		if !exists {
			group = &findingGroup{
				Type:      typeValue,
				Severity:  severity,
				Title:     title,
				Instances: make([]findingInstance, 0),
			}
			groups[key] = group
			groupOrder = append(groupOrder, key)
		}
		group.InstanceCount++
		group.TotalCount += count
		if len(group.Instances) < topNLimit {
			group.Instances = append(group.Instances, instance)
		}
	}

	bySeverity := make(map[string][]findingGroup)
	severityOrder := make([]string, 0)
	for _, key := range groupOrder {
		if _, exists := bySeverity[key.severity]; !exists {
			severityOrder = append(severityOrder, key.severity)
		}
		bySeverity[key.severity] = append(bySeverity[key.severity], *groups[key])
	}

	sort.SliceStable(severityOrder, func(i, j int) bool {
		return findingSeverityRank(severityOrder[i]) > findingSeverityRank(severityOrder[j])
	})

	buckets := make([]severityBucket, 0, len(severityOrder))
	for _, severity := range severityOrder {
		buckets = append(buckets, severityBucket{
			Severity: severity,
			Groups:   bySeverity[severity],
		})
	}
	return buckets, nil
}
