package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeAIStore struct {
	report aiAnalysisResponse
	ok     bool
	stored bool
}

func (s *fakeAIStore) Fetch(ctx context.Context, uploadID int64, payloadHash, model string) (aiAnalysisResponse, bool, error) {
	return s.report, s.ok, nil
}

func (s *fakeAIStore) Store(ctx context.Context, uploadID int64, payloadHash string, report aiAnalysisResponse) error {
	s.stored = true
	s.report = report
	return nil
}

type fakeAIClient struct {
	response string
	called   bool
}

func (c *fakeAIClient) Generate(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	c.called = true
	return c.response, nil
}

func TestBuildAIAnalysisPayloadSanitizesAndExcludesRawEvents(t *testing.T) {
	longName := strings.Repeat("a", 250) + "\x00.log"
	status := uploadStatusResponse{
		ID:        7,
		LogType:   logTypeVPC,
		FileName:  longName,
		Status:    "completed",
		CreatedAt: time.Unix(1716220000, 0).UTC(),
	}
	summary := summaryPayload{
		TotalLines:    10,
		TotalRecords:  9,
		ParsedPercent: 90,
		AcceptedCount: 6,
		RejectedCount: 3,
	}

	payloadJSON, payloadHash, err := buildAIAnalysisPayload(status, summary, nil, nil, chartData{})
	if err != nil {
		t.Fatalf("buildAIAnalysisPayload error: %v", err)
	}
	if payloadHash == "" {
		t.Fatalf("expected payload hash")
	}
	payload := string(payloadJSON)
	if strings.Contains(payload, "\x00") {
		t.Fatalf("payload contains control character")
	}
	if strings.Contains(payload, "raw_line") || strings.Contains(payload, "event_logs") {
		t.Fatalf("payload should not include raw event data: %s", payload)
	}
	if strings.Contains(payload, strings.Repeat("a", 201)) {
		t.Fatalf("payload did not cap long strings")
	}
}

func TestNewClaudeClientReturnsConfiguredClient(t *testing.T) {
	client, err := newClaudeClient(config{
		ClaudeAPIKey: "sk-test",
		ClaudeModel:  "claude-3-5-haiku-latest",
	})
	if err != nil {
		t.Fatalf("newClaudeClient error: %v", err)
	}
	if _, ok := client.(*claudeClient); !ok {
		t.Fatalf("client type = %T, want *claudeClient", client)
	}
}

func TestSelectedAIModelDefaultAndOverride(t *testing.T) {
	if got := selectedAIModel(config{}); got != "claude-3-5-haiku-latest" {
		t.Fatalf("selectedAIModel = %q, want default haiku", got)
	}
	if got := selectedAIModel(config{ClaudeModel: "claude-test"}); got != "claude-test" {
		t.Fatalf("selectedAIModel = %q, want claude-test", got)
	}
}

func TestNewClaudeClientRequiresAnthropicKey(t *testing.T) {
	_, err := newClaudeClient(config{})
	if !errors.Is(err, errMissingAIAPIKey) {
		t.Fatalf("error = %v, want errMissingAIAPIKey", err)
	}
}

func TestGetOrCreateAIAnalysisReturnsCachedReportWithoutClient(t *testing.T) {
	store := &fakeAIStore{
		ok: true,
		report: aiAnalysisResponse{
			Summary:            "Cached report.",
			Threats:            []string{},
			FalsePositives:     []string{},
			RecommendedActions: []string{},
			Model:              "claude-3-5-haiku-latest",
			GeneratedAt:        time.Unix(1716220000, 0).UTC().Format(time.RFC3339),
		},
	}
	factoryCalled := false

	report, err := getOrCreateAIAnalysis(
		context.Background(),
		store,
		func() (aiAnalysisClient, error) {
			factoryCalled = true
			return &fakeAIClient{}, nil
		},
		7,
		"hash",
		[]byte(`{}`),
		"claude-3-5-haiku-latest",
		time.Now(),
	)
	if err != nil {
		t.Fatalf("getOrCreateAIAnalysis error: %v", err)
	}
	if report.Summary != "Cached report." {
		t.Fatalf("summary = %q", report.Summary)
	}
	if factoryCalled {
		t.Fatalf("client factory should not be called for cached reports")
	}
	if store.stored {
		t.Fatalf("cached report should not be stored again")
	}
}

func TestGetOrCreateAIAnalysisStoresGeneratedReport(t *testing.T) {
	store := &fakeAIStore{}
	client := &fakeAIClient{
		response: `{
			"summary": "External 203.0.113.10 generated 10 SSH attempts.",
			"threats": ["203.0.113.10 generated 10 SSH attempts to port 22."],
			"false_positives": [],
			"recommended_actions": ["Review security group rules for SSH on target hosts."]
		}`,
	}
	generatedAt := time.Unix(1716220000, 0).UTC()

	report, err := getOrCreateAIAnalysis(
		context.Background(),
		store,
		func() (aiAnalysisClient, error) {
			return client, nil
		},
		7,
		"hash",
		[]byte(`{"summary":{"total_records":10}}`),
		"claude-3-5-haiku-latest",
		generatedAt,
	)
	if err != nil {
		t.Fatalf("getOrCreateAIAnalysis error: %v", err)
	}
	if !client.called {
		t.Fatalf("expected client to be called")
	}
	if !store.stored {
		t.Fatalf("expected report to be stored")
	}
	if report.Model != "claude-3-5-haiku-latest" {
		t.Fatalf("model = %q", report.Model)
	}
	if report.GeneratedAt != generatedAt.Format(time.RFC3339) {
		t.Fatalf("generated_at = %q", report.GeneratedAt)
	}
}

func TestParseAIAnalysisReportRejectsMalformedJSON(t *testing.T) {
	if _, err := parseAIAnalysisReport("{not-json"); err == nil {
		t.Fatalf("expected malformed JSON error")
	}
}

func TestParseAIAnalysisReportExtractsFencedJSON(t *testing.T) {
	report, err := parseAIAnalysisReport("```json\n{\"summary\":\"ok\",\"threats\":[],\"false_positives\":[],\"recommended_actions\":[]}\n```")
	if err != nil {
		t.Fatalf("parseAIAnalysisReport error: %v", err)
	}
	if report.Summary != "ok" {
		t.Fatalf("summary = %q, want ok", report.Summary)
	}
}

func TestParseAIAnalysisReportReportsTruncatedJSON(t *testing.T) {
	_, err := parseAIAnalysisReport("{\"summary\":\"partial\"")
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error = %v, want truncated JSON error", err)
	}
}
