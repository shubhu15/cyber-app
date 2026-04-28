package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const maxUploadBytes = 10 * 1024 * 1024

type application struct {
	config  config
	db      *sql.DB
	storage storage
}

type contextKey string

const userContextKey contextKey = "sessionUser"

type sessionUser struct {
	ID    int64
	Email string
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type messageResponse struct {
	Message string `json:"message"`
}

type uploadCreatedResponse struct {
	UploadID int64  `json:"upload_id"`
	Status   string `json:"status"`
}

type uploadListItem struct {
	ID         int64      `json:"id"`
	LogType    string     `json:"log_type"`
	FileName   string     `json:"file_name"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type uploadStatusResponse struct {
	ID                 int64      `json:"id"`
	LogType            string     `json:"log_type"`
	FileName           string     `json:"file_name"`
	Status             string     `json:"status"`
	CreatedAt          time.Time  `json:"created_at"`
	StartedAt          *time.Time `json:"started_at,omitempty"`
	FinishedAt         *time.Time `json:"finished_at,omitempty"`
	ErrorMessage       string     `json:"error_message,omitempty"`
	TotalLines         int        `json:"total_lines"`
	ParsedLines        int        `json:"parsed_lines"`
	ProgressPercentage int        `json:"progress_percentage"`
}

type resultsResponse struct {
	Upload   uploadStatusResponse `json:"upload"`
	Summary  summaryPayload       `json:"summary"`
	Findings []findingPayload     `json:"findings"`
	Timeline []timelineEntry      `json:"timeline"`
	Charts   chartData            `json:"charts"`
	Events   []eventPayload       `json:"events"`
}

type summaryPayload struct {
	TotalRecords  int    `json:"total_records"`
	AcceptedCount int    `json:"accepted_count"`
	RejectedCount int    `json:"rejected_count"`
	ParseErrors   int    `json:"parse_errors"`
	AISummary     string `json:"ai_summary"`
}

type findingPayload struct {
	Type        string         `json:"type"`
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	FirstSeenAt *string        `json:"first_seen_at,omitempty"`
	LastSeenAt  *string        `json:"last_seen_at,omitempty"`
	Count       int            `json:"count"`
	Metadata    map[string]any `json:"metadata"`
}

type eventPayload struct {
	ID            int64   `json:"id"`
	Version       int     `json:"version"`
	AccountID     string  `json:"account_id,omitempty"`
	InterfaceID   string  `json:"interface_id,omitempty"`
	SrcAddr       string  `json:"src_addr,omitempty"`
	DstAddr       string  `json:"dst_addr,omitempty"`
	SrcPort       *int    `json:"src_port,omitempty"`
	DstPort       *int    `json:"dst_port,omitempty"`
	Protocol      *int    `json:"protocol,omitempty"`
	ProtocolLabel string  `json:"protocol_label"`
	Packets       *int64  `json:"packets,omitempty"`
	Bytes         *int64  `json:"bytes,omitempty"`
	StartTime     *string `json:"start_time,omitempty"`
	EndTime       *string `json:"end_time,omitempty"`
	Action        string  `json:"action,omitempty"`
	LogStatus     string  `json:"log_status"`
	RawLine       string  `json:"raw_line"`
}

func (app *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/register", app.handleRegister)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/uploads", app.requireSession(app.routeUploadsRoot))
	mux.HandleFunc("/uploads/", app.requireSession(app.routeUploadByID))
	return app.withCORS(mux)
}

func (app *application) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}
	writeJSON(w, http.StatusOK, messageResponse{Message: "Backend is healthy."})
}

func (app *application) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	var input registerRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Invalid JSON body."})
		return
	}

	email, password, err := normalizeCredentials(input.Email, input.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: err.Error()})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to secure password."})
		return
	}

	_, err = app.db.ExecContext(r.Context(), `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
	`, email, string(passwordHash))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, messageResponse{Message: "User already exists."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to save user."})
		return
	}

	writeJSON(w, http.StatusCreated, messageResponse{Message: "Registration successful."})
}

func (app *application) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	email, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="simple-log-analyser"`)
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Missing Basic Auth credentials."})
		return
	}

	email, password, err := normalizeCredentials(email, password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: err.Error()})
		return
	}

	var user sessionUser
	var passwordHash string
	err = app.db.QueryRowContext(r.Context(), `
		SELECT id, email, password_hash
		FROM users
		WHERE email = $1
	`, email).Scan(&user.ID, &user.Email, &passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Invalid email or password."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read user."})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Invalid email or password."})
		return
	}

	token, err := generateSessionToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to create session."})
		return
	}

	if err := app.createSession(r.Context(), user.ID, token); err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to create session."})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     app.config.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   app.config.AppEnv == "production",
		Expires:  time.Now().Add(app.config.SessionTTL),
		MaxAge:   int(app.config.SessionTTL.Seconds()),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (app *application) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	cookie, err := r.Cookie(app.config.SessionCookieName)
	if err == nil && strings.TrimSpace(cookie.Value) != "" {
		hash := hashSessionToken(cookie.Value)
		if _, deleteErr := app.db.ExecContext(r.Context(), `
			DELETE FROM sessions
			WHERE token_hash = $1
		`, hash); deleteErr != nil {
			log.Printf("delete session: %v", deleteErr)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     app.config.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   app.config.AppEnv == "production",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (app *application) routeUploadsRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		app.handleListUploads(w, r)
	case http.MethodPost:
		app.handleCreateUpload(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
	}
}

func (app *application) routeUploadByID(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/uploads/")
	if trimmed == "" {
		writeJSON(w, http.StatusNotFound, messageResponse{Message: "Upload not found."})
		return
	}

	if strings.HasSuffix(trimmed, "/results") {
		idText := strings.TrimSuffix(strings.TrimSuffix(trimmed, "/results"), "/")
		uploadID, err := strconv.ParseInt(idText, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Invalid upload id."})
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
			return
		}
		app.handleUploadResults(w, r, uploadID)
		return
	}

	uploadID, err := strconv.ParseInt(strings.TrimSuffix(trimmed, "/"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Invalid upload id."})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}
	app.handleUploadStatus(w, r, uploadID)
}

func (app *application) handleListUploads(w http.ResponseWriter, r *http.Request) {
	user := sessionUserFromContext(r.Context())
	rows, err := app.db.QueryContext(r.Context(), `
		SELECT id, log_type, file_name, status, created_at, finished_at
		FROM uploads
		WHERE user_id = $1 AND log_type = $2
		ORDER BY created_at DESC
	`, user.ID, logTypeVPC)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to list uploads."})
		return
	}
	defer rows.Close()

	items := make([]uploadListItem, 0)
	for rows.Next() {
		var item uploadListItem
		var finishedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.LogType, &item.FileName, &item.Status, &item.CreatedAt, &finishedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to list uploads."})
			return
		}
		if finishedAt.Valid {
			value := finishedAt.Time
			item.FinishedAt = &value
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, items)
}

func (app *application) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	user := sessionUserFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes+1024)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Invalid upload form or file exceeds 10 MB."})
		return
	}

	if totalFiles(r.MultipartForm.File) != 1 {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Upload exactly one flow-log file."})
		return
	}

	logType := strings.TrimSpace(r.FormValue("log_type"))
	if logType == "" {
		logType = logTypeVPC
	}
	if logType != logTypeVPC {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Unsupported log type."})
		return
	}

	fileHeader, err := requireSingleFile(r.MultipartForm.File["file"])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: err.Error()})
		return
	}

	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))
	if ext != "" && ext != ".log" && ext != ".txt" {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Only plain-text .log or .txt files are supported."})
		return
	}
	if fileHeader.Size > maxUploadBytes {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "File exceeds the 10 MB upload limit."})
		return
	}

	uploadID, err := app.createUploadRow(r.Context(), user.ID, fileHeader.Filename, logType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to create upload."})
		return
	}

	src, err := fileHeader.Open()
	if err != nil {
		_ = app.deleteUploadRow(r.Context(), uploadID)
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read uploaded file."})
		return
	}
	defer src.Close()

	fileRef, err := app.storage.Save(uploadID, fileHeader.Filename, src)
	if err != nil {
		_ = app.deleteUploadRow(r.Context(), uploadID)
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to store uploaded file."})
		return
	}

	if _, err := app.db.ExecContext(r.Context(), `
		UPDATE uploads
		SET file_ref = $2
		WHERE id = $1
	`, uploadID, fileRef); err != nil {
		_ = app.deleteUploadRow(r.Context(), uploadID)
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to finalize upload."})
		return
	}

	writeJSON(w, http.StatusAccepted, uploadCreatedResponse{
		UploadID: uploadID,
		Status:   "pending",
	})
}

func (app *application) handleUploadStatus(w http.ResponseWriter, r *http.Request, uploadID int64) {
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
	writeJSON(w, http.StatusOK, status)
}

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
	findings, err := app.fetchFindings(r.Context(), uploadID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read findings."})
		return
	}
	events, err := app.fetchEvents(r.Context(), uploadID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read events."})
		return
	}

	writeJSON(w, http.StatusOK, resultsResponse{
		Upload:   status,
		Summary:  summary,
		Findings: findings,
		Timeline: timeline,
		Charts:   charts,
		Events:   events,
	})
}

func (app *application) fetchUploadStatus(ctx context.Context, userID, uploadID int64) (uploadStatusResponse, bool, error) {
	row := app.db.QueryRowContext(ctx, `
		SELECT id, log_type, file_name, status, created_at, started_at, finished_at, COALESCE(error_message, ''), total_lines, parsed_lines
		FROM uploads
		WHERE id = $1 AND user_id = $2 AND log_type = $3
	`, uploadID, userID, logTypeVPC)

	var status uploadStatusResponse
	var startedAt sql.NullTime
	var finishedAt sql.NullTime
	if err := row.Scan(&status.ID, &status.LogType, &status.FileName, &status.Status, &status.CreatedAt, &startedAt, &finishedAt, &status.ErrorMessage, &status.TotalLines, &status.ParsedLines); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uploadStatusResponse{}, false, nil
		}
		return uploadStatusResponse{}, false, err
	}
	if startedAt.Valid {
		value := startedAt.Time
		status.StartedAt = &value
	}
	if finishedAt.Valid {
		value := finishedAt.Time
		status.FinishedAt = &value
	}
	status.ProgressPercentage = computeProgressPercentage(status.Status, status.TotalLines, status.ParsedLines)
	return status, true, nil
}

func computeProgressPercentage(status string, totalLines, parsedLines int) int {
	switch status {
	case "completed":
		return 100
	case "failed":
		if totalLines > 0 {
			value := (parsedLines * 100) / totalLines
			if value > 100 {
				return 100
			}
			return value
		}
		return 0
	default:
		if totalLines <= 0 {
			return 0
		}
		value := (parsedLines * 100) / totalLines
		if value > 99 {
			return 99
		}
		return value
	}
}

func (app *application) fetchSummary(ctx context.Context, uploadID int64) (summaryPayload, []timelineEntry, chartData, error) {
	row := app.db.QueryRowContext(ctx, `
		SELECT total_records, accepted_count, rejected_count, parse_errors,
		       top_src_ips_json, top_dst_ports_json, top_rejected_src_ips_json, timeline_json, ai_summary
		FROM summaries
		WHERE upload_id = $1
	`, uploadID)

	var payload summaryPayload
	var topSrcJSON string
	var topDstPortsJSON string
	var topRejectedSrcJSON string
	var timelineJSON string
	if err := row.Scan(
		&payload.TotalRecords,
		&payload.AcceptedCount,
		&payload.RejectedCount,
		&payload.ParseErrors,
		&topSrcJSON,
		&topDstPortsJSON,
		&topRejectedSrcJSON,
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

	var topSrcIPs []chartPoint
	if err := json.Unmarshal([]byte(topSrcJSON), &topSrcIPs); err != nil {
		return summaryPayload{}, nil, chartData{}, err
	}
	var topDstPorts []chartPoint
	if err := json.Unmarshal([]byte(topDstPortsJSON), &topDstPorts); err != nil {
		return summaryPayload{}, nil, chartData{}, err
	}
	var topRejected []chartPoint
	if err := json.Unmarshal([]byte(topRejectedSrcJSON), &topRejected); err != nil {
		return summaryPayload{}, nil, chartData{}, err
	}

	topInterfaces, err := app.fetchTopInterfaces(ctx, uploadID)
	if err != nil {
		return summaryPayload{}, nil, chartData{}, err
	}
	burstWindows, err := app.fetchBurstWindows(ctx, uploadID)
	if err != nil {
		return summaryPayload{}, nil, chartData{}, err
	}

	charts := chartData{
		ActionCounts: []chartPoint{
			{Label: actionAccept, Count: int64(payload.AcceptedCount)},
			{Label: actionReject, Count: int64(payload.RejectedCount)},
		},
		TopSrcIPs:         ensureChartPoints(topSrcIPs),
		TopDstPorts:       ensureChartPoints(topDstPorts),
		TopRejectedSrcIPs: ensureChartPoints(topRejected),
		TopInterfaces:     ensureChartPoints(topInterfaces),
		BurstWindows:      burstWindows,
	}

	return payload, timeline, charts, nil
}

func (app *application) fetchTopInterfaces(ctx context.Context, uploadID int64) ([]chartPoint, error) {
	rows, err := app.db.QueryContext(ctx, `
		SELECT interface_id, COUNT(*)
		FROM event_logs
		WHERE upload_id = $1 AND interface_id IS NOT NULL AND interface_id <> ''
		GROUP BY interface_id
		ORDER BY COUNT(*) DESC, interface_id ASC
		LIMIT 10
	`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	points := make([]chartPoint, 0)
	for rows.Next() {
		var label string
		var count int64
		if err := rows.Scan(&label, &count); err != nil {
			return nil, err
		}
		points = append(points, chartPoint{Label: label, Count: count})
	}
	return points, nil
}

func (app *application) fetchBurstWindows(ctx context.Context, uploadID int64) ([]burstWindow, error) {
	rows, err := app.db.QueryContext(ctx, `
		SELECT (FLOOR(EXTRACT(EPOCH FROM start_time) / 300)::BIGINT * 300) AS bucket_epoch, COUNT(*)
		FROM event_logs
		WHERE upload_id = $1 AND start_time IS NOT NULL
		GROUP BY bucket_epoch
		ORDER BY COUNT(*) DESC, bucket_epoch ASC
		LIMIT 6
	`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	windows := make([]burstWindow, 0)
	for rows.Next() {
		var epoch int64
		var count int64
		if err := rows.Scan(&epoch, &count); err != nil {
			return nil, err
		}
		windows = append(windows, burstWindow{
			Bucket: time.Unix(epoch, 0).UTC().Format(time.RFC3339),
			Count:  count,
		})
	}
	return windows, nil
}

func ensureChartPoints(points []chartPoint) []chartPoint {
	if points == nil {
		return []chartPoint{}
	}
	return points
}

func (app *application) fetchFindings(ctx context.Context, uploadID int64) ([]findingPayload, error) {
	rows, err := app.db.QueryContext(ctx, `
		SELECT type, severity, title, description, first_seen_at, last_seen_at, count, metadata_json
		FROM findings
		WHERE upload_id = $1
		ORDER BY count DESC, created_at ASC
	`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := make([]findingPayload, 0)
	for rows.Next() {
		var finding findingPayload
		var firstSeen sql.NullTime
		var lastSeen sql.NullTime
		var metadataJSON string
		if err := rows.Scan(&finding.Type, &finding.Severity, &finding.Title, &finding.Description, &firstSeen, &lastSeen, &finding.Count, &metadataJSON); err != nil {
			return nil, err
		}
		if firstSeen.Valid {
			value := firstSeen.Time.UTC().Format(time.RFC3339)
			finding.FirstSeenAt = &value
		}
		if lastSeen.Valid {
			value := lastSeen.Time.UTC().Format(time.RFC3339)
			finding.LastSeenAt = &value
		}
		if strings.TrimSpace(metadataJSON) == "" {
			finding.Metadata = map[string]any{}
		} else if err := json.Unmarshal([]byte(metadataJSON), &finding.Metadata); err != nil {
			return nil, err
		}
		if finding.Metadata == nil {
			finding.Metadata = map[string]any{}
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (app *application) fetchEvents(ctx context.Context, uploadID int64) ([]eventPayload, error) {
	rows, err := app.db.QueryContext(ctx, `
		SELECT id, version, COALESCE(account_id, ''), COALESCE(interface_id, ''), COALESCE(src_addr, ''),
		       COALESCE(dst_addr, ''), src_port, dst_port, protocol, packets, bytes, start_time, end_time,
		       COALESCE(action, ''), log_status, raw_line
		FROM event_logs
		WHERE upload_id = $1
		ORDER BY start_time ASC NULLS LAST, id ASC
	`, uploadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]eventPayload, 0)
	for rows.Next() {
		var event eventPayload
		var srcPort sql.NullInt64
		var dstPort sql.NullInt64
		var protocol sql.NullInt64
		var packets sql.NullInt64
		var bytesValue sql.NullInt64
		var startTime sql.NullTime
		var endTime sql.NullTime

		if err := rows.Scan(
			&event.ID,
			&event.Version,
			&event.AccountID,
			&event.InterfaceID,
			&event.SrcAddr,
			&event.DstAddr,
			&srcPort,
			&dstPort,
			&protocol,
			&packets,
			&bytesValue,
			&startTime,
			&endTime,
			&event.Action,
			&event.LogStatus,
			&event.RawLine,
		); err != nil {
			return nil, err
		}

		if srcPort.Valid {
			value := int(srcPort.Int64)
			event.SrcPort = &value
		}
		if dstPort.Valid {
			value := int(dstPort.Int64)
			event.DstPort = &value
		}
		if protocol.Valid {
			value := int(protocol.Int64)
			event.Protocol = &value
		}
		if packets.Valid {
			value := packets.Int64
			event.Packets = &value
		}
		if bytesValue.Valid {
			value := bytesValue.Int64
			event.Bytes = &value
		}
		if startTime.Valid {
			value := startTime.Time.UTC().Format(time.RFC3339)
			event.StartTime = &value
		}
		if endTime.Valid {
			value := endTime.Time.UTC().Format(time.RFC3339)
			event.EndTime = &value
		}
		event.ProtocolLabel = protocolLabel(event.Protocol)
		events = append(events, event)
	}
	return events, nil
}

func (app *application) createUploadRow(ctx context.Context, userID int64, fileName, logType string) (int64, error) {
	var uploadID int64
	err := app.db.QueryRowContext(ctx, `
		INSERT INTO uploads (user_id, file_name, log_type, storage_type, file_ref, status, total_lines, parsed_lines)
		VALUES ($1, $2, $3, 'local', '', 'pending', 0, 0)
		RETURNING id
	`, userID, fileName, logType).Scan(&uploadID)
	return uploadID, err
}

func (app *application) deleteUploadRow(ctx context.Context, uploadID int64) error {
	_, err := app.db.ExecContext(ctx, `DELETE FROM uploads WHERE id = $1`, uploadID)
	return err
}

func (app *application) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := app.authenticateRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Authentication required."})
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next(w, r.WithContext(ctx))
	}
}

func (app *application) authenticateRequest(r *http.Request) (*sessionUser, error) {
	cookie, err := r.Cookie(app.config.SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return nil, errors.New("missing session")
	}

	hash := hashSessionToken(cookie.Value)
	var user sessionUser
	err = app.db.QueryRowContext(r.Context(), `
		SELECT users.id, users.email
		FROM sessions
		JOIN users ON users.id = sessions.user_id
		WHERE sessions.token_hash = $1
		  AND sessions.expires_at > NOW()
	`, hash).Scan(&user.ID, &user.Email)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (app *application) createSession(ctx context.Context, userID int64, token string) error {
	hash := hashSessionToken(token)
	_, err := app.db.ExecContext(ctx, `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, hash, time.Now().Add(app.config.SessionTTL))
	return err
}

func (app *application) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if _, ok := app.config.AllowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeCredentials(email, password string) (string, string, error) {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	if cleanEmail == "" {
		return "", "", errors.New("Email is required.")
	}
	if !strings.Contains(cleanEmail, "@") {
		return "", "", errors.New("Enter a valid email address.")
	}
	if password == "" {
		return "", "", errors.New("Password is required.")
	}
	return cleanEmail, password, nil
}

func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionUserFromContext(ctx context.Context) sessionUser {
	user, _ := ctx.Value(userContextKey).(*sessionUser)
	if user == nil {
		return sessionUser{}
	}
	return *user
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response: %v", err)
	}
}

func requireSingleFile(files []*multipart.FileHeader) (*multipart.FileHeader, error) {
	if len(files) != 1 {
		return nil, fmt.Errorf("Upload exactly one file.")
	}
	return files[0], nil
}

func totalFiles(groups map[string][]*multipart.FileHeader) int {
	total := 0
	for _, files := range groups {
		total += len(files)
	}
	return total
}

func nullableString(value string) any {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return nil
	}
	return clean
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
