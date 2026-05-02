package main

import (
	"database/sql"
	"time"
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
