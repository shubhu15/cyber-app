package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

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
