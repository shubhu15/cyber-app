package main

import (
	"testing"
	"time"
)

func TestParseVpcFlowLine(t *testing.T) {
	line := "2 123456789012 eni-12345678 10.0.1.10 10.0.2.20 443 51514 6 10 840 1716220000 1716220060 ACCEPT OK"
	parsed, ok := parseVpcFlowLine(line)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if parsed.Version != 2 {
		t.Fatalf("version = %d", parsed.Version)
	}
	if parsed.AccountID != "123456789012" {
		t.Fatalf("account_id = %q", parsed.AccountID)
	}
	if parsed.SrcPort == nil || *parsed.SrcPort != 443 {
		t.Fatalf("src_port = %v", parsed.SrcPort)
	}
	if parsed.Protocol == nil || *parsed.Protocol != 6 {
		t.Fatalf("protocol = %v", parsed.Protocol)
	}
	if parsed.Action != actionAccept {
		t.Fatalf("action = %q", parsed.Action)
	}
	if parsed.LogStatus != logStatusOK {
		t.Fatalf("log_status = %q", parsed.LogStatus)
	}
	if parsed.StartTime == nil || parsed.EndTime == nil {
		t.Fatalf("expected timestamps")
	}
}

func TestParseVpcFlowLineMalformedFieldCount(t *testing.T) {
	line := "2 123456789012 eni-12345678 10.0.1.10 10.0.2.20 443"
	if _, ok := parseVpcFlowLine(line); ok {
		t.Fatalf("expected parse failure")
	}
}

func TestParseVpcFlowLineAllowsPlaceholders(t *testing.T) {
	line := "2 123456789012 eni-12345678 10.0.1.10 10.0.2.20 - - 6 - - 1716220000 1716220060 REJECT SKIPDATA"
	parsed, ok := parseVpcFlowLine(line)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if parsed.SrcPort != nil {
		t.Fatalf("src_port = %v", parsed.SrcPort)
	}
	if parsed.Packets != nil {
		t.Fatalf("packets = %v", parsed.Packets)
	}
	if parsed.LogStatus != logStatusSkipData {
		t.Fatalf("log_status = %q", parsed.LogStatus)
	}
}

func TestProtocolLabel(t *testing.T) {
	value := 6
	if got := protocolLabel(&value); got != "TCP" {
		t.Fatalf("protocolLabel() = %q", got)
	}
}

func TestFindingsAggregatorRejectedTraffic(t *testing.T) {
	agg := newFindingsAggregator()
	for i := 0; i < 4; i++ {
		port := 2000 + i
		parsed := &parsedVpcFlowLine{
			SrcAddr:   "10.0.0.8",
			DstPort:   &port,
			Action:    actionReject,
			LogStatus: logStatusOK,
			StartTime: mustUnixTime(t, 1716220000+int64(i)),
		}
		agg.add(parsed)
	}

	findings := agg.build()
	found := false
	for _, finding := range findings {
		if finding.Type == findingRejectedTraffic {
			found = true
			if finding.Count != 4 {
				t.Fatalf("count = %d", finding.Count)
			}
		}
	}
	if !found {
		t.Fatalf("expected rejected traffic finding")
	}
}

func TestFindingsAggregatorHighPortScan(t *testing.T) {
	agg := newFindingsAggregator()
	for i := 0; i < 10; i++ {
		port := 1000 + i
		parsed := &parsedVpcFlowLine{
			SrcAddr:   "10.0.0.44",
			DstPort:   &port,
			Action:    actionAccept,
			LogStatus: logStatusOK,
			StartTime: mustUnixTime(t, 1716220000+int64(i)),
		}
		agg.add(parsed)
	}

	findings := agg.build()
	found := false
	for _, finding := range findings {
		if finding.Type == findingHighPortScan {
			found = true
			if finding.Count != 10 {
				t.Fatalf("count = %d", finding.Count)
			}
		}
	}
	if !found {
		t.Fatalf("expected high port scan finding")
	}
}

func TestFindingsAggregatorVisibilityGap(t *testing.T) {
	agg := newFindingsAggregator()
	agg.add(&parsedVpcFlowLine{
		SrcAddr:   "10.0.0.12",
		LogStatus: logStatusSkipData,
		StartTime: mustUnixTime(t, 1716220000),
	})

	findings := agg.build()
	found := false
	for _, finding := range findings {
		if finding.Type == findingVisibilityGap {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected visibility gap finding")
	}
}

func mustUnixTime(t *testing.T, unix int64) *time.Time {
	t.Helper()
	value := time.Unix(unix, 0).UTC()
	return &value
}
