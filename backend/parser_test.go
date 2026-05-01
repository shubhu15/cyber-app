package main

import (
	"strconv"
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

func TestFindingsAggregatorSSHBruteForceExternalSource(t *testing.T) {
	agg := newFindingsAggregator()
	port := 22
	for i := 0; i < sshBruteForceThreshold; i++ {
		agg.add(&parsedVpcFlowLine{
			SrcAddr:   "203.0.113.10",
			DstAddr:   "10.0.1.10",
			DstPort:   &port,
			Action:    actionReject,
			LogStatus: logStatusOK,
			StartTime: mustUnixTime(t, 1716220000+int64(i)),
		})
	}

	finding := findFindingByType(agg.build(), findingSSHBruteForce)
	if finding == nil {
		t.Fatalf("expected SSH brute-force finding")
	}
	if finding.Count != sshBruteForceThreshold {
		t.Fatalf("count = %d, want %d", finding.Count, sshBruteForceThreshold)
	}
	if finding.Severity != "high" {
		t.Fatalf("severity = %q, want high", finding.Severity)
	}
	if finding.Metadata["service"] != "SSH" {
		t.Fatalf("service metadata = %v, want SSH", finding.Metadata["service"])
	}
}

func TestFindingsAggregatorSSHBruteForceIgnoresInternalSource(t *testing.T) {
	agg := newFindingsAggregator()
	port := 22
	for i := 0; i < sshBruteForceThreshold; i++ {
		agg.add(&parsedVpcFlowLine{
			SrcAddr:   "10.0.1.20",
			DstAddr:   "10.0.1.10",
			DstPort:   &port,
			Action:    actionReject,
			LogStatus: logStatusOK,
			StartTime: mustUnixTime(t, 1716220000+int64(i)),
		})
	}

	if finding := findFindingByType(agg.build(), findingSSHBruteForce); finding != nil {
		t.Fatalf("unexpected SSH brute-force finding for internal source")
	}
}

func TestFindingsAggregatorSuspiciousPortProbe(t *testing.T) {
	agg := newFindingsAggregator()
	port := 6379
	for i := 0; i < suspiciousProbeThreshold; i++ {
		agg.add(&parsedVpcFlowLine{
			SrcAddr:   "203.0.113.25",
			DstAddr:   "10.0.2.15",
			DstPort:   &port,
			Action:    actionReject,
			LogStatus: logStatusOK,
			StartTime: mustUnixTime(t, 1716220000+int64(i)),
		})
	}

	finding := findFindingByType(agg.build(), findingSuspiciousProbe)
	if finding == nil {
		t.Fatalf("expected suspicious probe finding")
	}
	if finding.Count != suspiciousProbeThreshold {
		t.Fatalf("count = %d, want %d", finding.Count, suspiciousProbeThreshold)
	}
	if finding.Metadata["service"] != "Redis" {
		t.Fatalf("service metadata = %v, want Redis", finding.Metadata["service"])
	}
}

func TestFindingsAggregatorSuspiciousPortProbeBelowThreshold(t *testing.T) {
	agg := newFindingsAggregator()
	port := 6379
	for i := 0; i < suspiciousProbeThreshold-1; i++ {
		agg.add(&parsedVpcFlowLine{
			SrcAddr:   "203.0.113.25",
			DstAddr:   "10.0.2.15",
			DstPort:   &port,
			Action:    actionReject,
			LogStatus: logStatusOK,
			StartTime: mustUnixTime(t, 1716220000+int64(i)),
		})
	}

	if finding := findFindingByType(agg.build(), findingSuspiciousProbe); finding != nil {
		t.Fatalf("unexpected suspicious probe finding below threshold")
	}
}

func TestFindingsAggregatorEmitsAllRejectedSources(t *testing.T) {
	agg := newFindingsAggregator()
	srcs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	for _, src := range srcs {
		for i := 0; i < rejectedTrafficThreshold; i++ {
			port := 9000 + i
			agg.add(&parsedVpcFlowLine{
				SrcAddr:   src,
				DstPort:   &port,
				Action:    actionReject,
				LogStatus: logStatusOK,
				StartTime: mustUnixTime(t, 1716220000+int64(i)),
			})
		}
	}

	findings := agg.build()
	rejected := 0
	for _, finding := range findings {
		if finding.Type == findingRejectedTraffic {
			rejected++
		}
	}
	if rejected != len(srcs) {
		t.Fatalf("rejected findings = %d, want %d (aggregator should emit all instances; cap is applied at API layer)", rejected, len(srcs))
	}
}

func TestBuildTimelineEntriesGroupsByType(t *testing.T) {
	first := time.Unix(1716220000, 0).UTC()
	mid := time.Unix(1716220060, 0).UTC()
	last := time.Unix(1716220120, 0).UTC()

	findings := []findingRecord{
		{Type: findingRejectedTraffic, Severity: "medium", Title: "Repeated rejected traffic from source",
			FirstSeenAt: &first, LastSeenAt: &mid, Count: 4},
		{Type: findingRejectedTraffic, Severity: "medium", Title: "Repeated rejected traffic from source",
			FirstSeenAt: &mid, LastSeenAt: &last, Count: 6},
		{Type: findingHighPortScan, Severity: "high", Title: "High destination-port fanout detected",
			FirstSeenAt: &first, LastSeenAt: &last, Count: 30},
	}

	entries := buildTimelineEntries(findings)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 (one per finding type)", len(entries))
	}
	if entries[0].Severity != "high" {
		t.Fatalf("entries[0].Severity = %q, want high (sorted by severity desc)", entries[0].Severity)
	}

	var rejected *timelineEntry
	for i := range entries {
		if entries[i].Type == findingRejectedTraffic {
			rejected = &entries[i]
		}
	}
	if rejected == nil {
		t.Fatalf("rejected timeline entry missing")
	}
	if rejected.InstanceCount != 2 {
		t.Fatalf("rejected.InstanceCount = %d, want 2", rejected.InstanceCount)
	}
	if rejected.TotalCount != 10 {
		t.Fatalf("rejected.TotalCount = %d, want 10", rejected.TotalCount)
	}
	if rejected.FirstSeenAt != first.Format(time.RFC3339) {
		t.Fatalf("rejected.FirstSeenAt = %q", rejected.FirstSeenAt)
	}
	if rejected.LastSeenAt != last.Format(time.RFC3339) {
		t.Fatalf("rejected.LastSeenAt = %q", rejected.LastSeenAt)
	}
}

func TestAnalysisAccumulatorLogStatusCounters(t *testing.T) {
	acc := newAnalysisAccumulator()

	cases := []string{
		logStatusOK, logStatusOK,
		logStatusNoData,
		logStatusSkipData, logStatusSkipData, logStatusSkipData,
	}
	for _, status := range cases {
		acc.addEvent(&parsedVpcFlowLine{
			Action:    actionAccept,
			LogStatus: status,
		})
	}

	if acc.parsedLines != len(cases) {
		t.Fatalf("parsedLines = %d, want %d", acc.parsedLines, len(cases))
	}
	if acc.noDataCount != 1 {
		t.Fatalf("noDataCount = %d, want 1", acc.noDataCount)
	}
	if acc.skipDataCount != 3 {
		t.Fatalf("skipDataCount = %d, want 3", acc.skipDataCount)
	}
}

func TestComputeParsedPercent(t *testing.T) {
	cases := []struct {
		total, parsed, want int
	}{
		{0, 0, 0},
		{10, 0, 0},
		{100, 50, 50},
		{3, 2, 66},
		{10, 10, 100},
		{10, 12, 100},
		{-1, 5, 0},
	}
	for _, tc := range cases {
		got := computeParsedPercent(tc.total, tc.parsed)
		if got != tc.want {
			t.Fatalf("computeParsedPercent(%d,%d) = %d, want %d", tc.total, tc.parsed, got, tc.want)
		}
	}
}

func TestIsInternalIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"172.16.0.5", true},
		{"172.31.255.254", true},
		{"172.32.0.1", false},
		{"172.15.0.1", false},
		{"192.168.1.1", true},
		{"192.169.0.1", false},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"", false},
		{"not-an-ip", false},
	}
	for _, tc := range cases {
		if got := isInternalIP(tc.ip); got != tc.want {
			t.Fatalf("isInternalIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestAccumulatorAggregatesConversationsAndInternalExternal(t *testing.T) {
	acc := newAnalysisAccumulator()
	dstPort := 443
	bytes1 := int64(500)
	bytes2 := int64(1500)
	bytes3 := int64(2000)

	acc.addEvent(&parsedVpcFlowLine{
		SrcAddr: "10.0.1.5", DstAddr: "10.0.2.7", DstPort: &dstPort,
		Bytes: &bytes1, Action: actionAccept, LogStatus: logStatusOK,
		StartTime: mustUnixTime(t, 1716220000),
	})
	acc.addEvent(&parsedVpcFlowLine{
		SrcAddr: "10.0.1.5", DstAddr: "10.0.2.7", DstPort: &dstPort,
		Bytes: &bytes2, Action: actionAccept, LogStatus: logStatusOK,
		StartTime: mustUnixTime(t, 1716220060),
	})
	acc.addEvent(&parsedVpcFlowLine{
		SrcAddr: "10.0.1.5", DstAddr: "8.8.8.8", DstPort: &dstPort,
		Bytes: &bytes3, Action: actionAccept, LogStatus: logStatusOK,
		StartTime: mustUnixTime(t, 1716220120),
	})

	convoKey := "10.0.1.5|10.0.2.7|443"
	convo, ok := acc.conversations[convoKey]
	if !ok {
		t.Fatalf("missing internal conversation %q", convoKey)
	}
	if convo.Flows != 2 {
		t.Fatalf("convo.Flows = %d, want 2", convo.Flows)
	}
	if convo.Bytes != bytes1+bytes2 {
		t.Fatalf("convo.Bytes = %d, want %d", convo.Bytes, bytes1+bytes2)
	}

	if acc.internalExternalFlows[bucketInternalToInternal] != 2 {
		t.Fatalf("internal→internal flows = %d, want 2", acc.internalExternalFlows[bucketInternalToInternal])
	}
	if acc.internalExternalFlows[bucketInternalToExternal] != 1 {
		t.Fatalf("internal→external flows = %d, want 1", acc.internalExternalFlows[bucketInternalToExternal])
	}
	if acc.internalExternalBytes[bucketInternalToExternal] != bytes3 {
		t.Fatalf("internal→external bytes = %d, want %d", acc.internalExternalBytes[bucketInternalToExternal], bytes3)
	}
}

func TestBuildChartsAppliesTop5Cap(t *testing.T) {
	acc := newAnalysisAccumulator()
	dstPort := 443
	for i := 0; i < 7; i++ {
		src := "10.0.0." + strconv.Itoa(10+i)
		dst := "10.0.1." + strconv.Itoa(10+i)
		bytes := int64(1000 * (i + 1))
		acc.addEvent(&parsedVpcFlowLine{
			SrcAddr: src, DstAddr: dst, DstPort: &dstPort,
			Bytes: &bytes, Action: actionAccept, LogStatus: logStatusOK,
			StartTime: mustUnixTime(t, 1716220000+int64(i*60)),
		})
	}

	charts := buildCharts(acc)
	if len(charts.TopSrcIPs) != topNLimit {
		t.Fatalf("TopSrcIPs = %d, want %d", len(charts.TopSrcIPs), topNLimit)
	}
	if len(charts.TopConversations) != topNLimit {
		t.Fatalf("TopConversations = %d, want %d", len(charts.TopConversations), topNLimit)
	}
	if charts.TopConversations[0].Bytes < charts.TopConversations[1].Bytes {
		t.Fatalf("TopConversations not sorted by bytes desc")
	}
	if len(charts.InternalExternal) != 4 {
		t.Fatalf("InternalExternal = %d, want 4 buckets", len(charts.InternalExternal))
	}
}

func mustUnixTime(t *testing.T, unix int64) *time.Time {
	t.Helper()
	value := time.Unix(unix, 0).UTC()
	return &value
}

func findFindingByType(findings []findingRecord, typeValue string) *findingRecord {
	for i := range findings {
		if findings[i].Type == typeValue {
			return &findings[i]
		}
	}
	return nil
}
