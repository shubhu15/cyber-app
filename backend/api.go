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
	"sort"
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

type meResponse struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
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
	Findings []severityBucket     `json:"findings"`
	Timeline []timelineEntry      `json:"timeline"`
	Charts   chartData            `json:"charts"`
}

type summaryPayload struct {
	TotalLines    int    `json:"total_lines"`
	TotalRecords  int    `json:"total_records"`
	ParsedPercent int    `json:"parsed_percent"`
	AcceptedCount int    `json:"accepted_count"`
	RejectedCount int    `json:"rejected_count"`
	NoDataCount   int    `json:"nodata_count"`
	SkipDataCount int    `json:"skipdata_count"`
	ParseErrors   int    `json:"parse_errors"`
	AISummary     string `json:"ai_summary"`
}

type findingInstance struct {
	Description string         `json:"description"`
	FirstSeenAt *string        `json:"first_seen_at,omitempty"`
	LastSeenAt  *string        `json:"last_seen_at,omitempty"`
	Count       int            `json:"count"`
	Metadata    map[string]any `json:"metadata"`
}

type findingGroup struct {
	Type          string            `json:"type"`
	Severity      string            `json:"severity"`
	Title         string            `json:"title"`
	InstanceCount int               `json:"instance_count"`
	TotalCount    int               `json:"total_count"`
	Instances     []findingInstance `json:"instances"`
}

type severityBucket struct {
	Severity string         `json:"severity"`
	Groups   []findingGroup `json:"groups"`
}

func (app *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/register", app.handleRegister)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/me", app.requireSession(app.handleMe))
	mux.HandleFunc("/session/refresh", app.requireSession(app.handleSessionRefresh))
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

func (app *application) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}
	user := sessionUserFromContext(r.Context())
	writeJSON(w, http.StatusOK, meResponse{ID: user.ID, Email: user.Email})
}

func (app *application) handleSessionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}
	cookie, err := r.Cookie(app.config.SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "No session cookie."})
		return
	}
	hash := hashSessionToken(cookie.Value)
	newExpiry := time.Now().Add(app.config.SessionTTL)
	result, err := app.db.ExecContext(r.Context(), `
		UPDATE sessions SET expires_at = $2 WHERE token_hash = $1 AND expires_at > NOW()
	`, hash, newExpiry)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to refresh session."})
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Session expired or not found."})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     app.config.SessionCookieName,
		Value:    cookie.Value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   app.config.AppEnv == "production",
		Expires:  newExpiry,
		MaxAge:   int(app.config.SessionTTL.Seconds()),
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

	if strings.HasSuffix(trimmed, "/ai-analysis") {
		idText := strings.TrimSuffix(strings.TrimSuffix(trimmed, "/ai-analysis"), "/")
		uploadID, err := strconv.ParseInt(idText, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Invalid upload id."})
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
			return
		}
		app.handleUploadAIAnalysis(w, r, uploadID)
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
	// todo: make log type as dropdown in frontend and validate here, for now we only support VPC flow logs so we can default to that if not provided
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
			return newAIAnalysisClient(app.config)
		},
		uploadID,
		payloadHash,
		payloadJSON,
		model,
		time.Now(),
	)
	if err != nil {
		if errors.Is(err, errMissingGeminiAPIKey) || errors.Is(err, errMissingAIAPIKey) {
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

func computeParsedPercent(totalLines, parsedLines int) int {
	if totalLines <= 0 {
		return 0
	}
	value := (parsedLines * 100) / totalLines
	if value > 100 {
		return 100
	}
	if value < 0 {
		return 0
	}
	return value
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
