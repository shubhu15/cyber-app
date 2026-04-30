package main

import (
	"os"
	"strings"
	"time"
)

type config struct {
	AppEnv             string
	Mode               string
	HTTPAddr           string
	DatabaseURL        string
	UploadDir          string
	SessionCookieName  string
	SessionTTL         time.Duration
	WorkerPollInterval time.Duration
	AllowedOrigins     map[string]struct{}
}

func loadConfig() config {
	origins := map[string]struct{}{
		"http://127.0.0.1:5173": {},
	}

	return config{
		AppEnv:             envOrDefault("APP_ENV", "development"),
		Mode:               envOrDefault("APP_MODE", "api"),
		HTTPAddr:           envOrDefault("HTTP_ADDR", ":8080"),
		DatabaseURL:        envOrDefault("DATABASE_URL", "postgres://localhost:5432/simple_log_analyser?sslmode=disable"),
		UploadDir:          envOrDefault("UPLOAD_DIR", "./data/uploads"),
		SessionCookieName:  envOrDefault("SESSION_COOKIE_NAME", "sla_session"),
		SessionTTL:         24 * time.Hour,
		WorkerPollInterval: 5 * time.Second,
		AllowedOrigins:     origins,
	}
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
