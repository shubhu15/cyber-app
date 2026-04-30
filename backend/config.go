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
	GeminiAPIKey       string
	GeminiModel        string
	ClaudeAPIKey       string
	ClaudeModel        string
}

func loadConfig() config {
	return config{
		AppEnv:             envOrDefault("APP_ENV", "development"),
		Mode:               envOrDefault("APP_MODE", "api"),
		HTTPAddr:           envOrDefault("HTTP_ADDR", ":8080"),
		DatabaseURL:        envOrDefault("DATABASE_URL", "postgres://localhost:5432/simple_log_analyser?sslmode=disable"),
		UploadDir:          envOrDefault("UPLOAD_DIR", "./data/uploads"),
		SessionCookieName:  envOrDefault("SESSION_COOKIE_NAME", "sla_session"),
		SessionTTL:         parseDuration(envOrDefault("SESSION_TTL", "2h")),
		WorkerPollInterval: 5 * time.Second,
		AllowedOrigins:     parseAllowedOrigins(envOrDefault("ALLOWED_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173")),
		GeminiAPIKey:       envOrDefault("GEMINI_API_KEY", ""),
		GeminiModel:        envOrDefault("GEMINI_MODEL", "gemini-2.5-flash"),
		ClaudeAPIKey:       envOrDefault("ANTHROPIC_API_KEY", ""),
		ClaudeModel:        envOrDefault("CLAUDE_MODEL", "claude-3-5-haiku-latest"),
	}
}

// parseAllowedOrigins converts a comma-separated list of origins into a set.
// Whitespace and trailing slashes are trimmed; empty entries are skipped.
func parseAllowedOrigins(raw string) map[string]struct{} {
	origins := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		origin := strings.TrimRight(strings.TrimSpace(part), "/")
		if origin != "" {
			origins[origin] = struct{}{}
		}
	}
	return origins
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 2 * time.Hour
	}
	return d
}
