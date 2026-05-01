package main

import "time"

type parsedVpcFlowLine struct {
	Version     int
	AccountID   string
	InterfaceID string
	SrcAddr     string
	DstAddr     string
	SrcPort     *int
	DstPort     *int
	Protocol    *int
	Packets     *int64
	Bytes       *int64
	StartTime   *time.Time
	EndTime     *time.Time
	Action      string
	LogStatus   string
}

type timelineEntry struct {
	Type          string `json:"type"`
	Severity      string `json:"severity"`
	Title         string `json:"title"`
	FirstSeenAt   string `json:"first_seen_at"`
	LastSeenAt    string `json:"last_seen_at"`
	InstanceCount int    `json:"instance_count"`
	TotalCount    int    `json:"total_count"`
}

type chartPoint struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

type burstWindow struct {
	Bucket string `json:"bucket"`
	Count  int64  `json:"count"`
}

type conversation struct {
	SrcAddr string `json:"src_addr"`
	DstAddr string `json:"dst_addr"`
	DstPort *int   `json:"dst_port"`
	Bytes   int64  `json:"bytes"`
	Flows   int64  `json:"flows"`
}

type internalExternalBucket struct {
	Bucket string `json:"bucket"`
	Flows  int64  `json:"flows"`
	Bytes  int64  `json:"bytes"`
}

type chartData struct {
	TopSrcIPs         []chartPoint             `json:"top_src_ips"`
	TopDstPorts       []chartPoint             `json:"top_dst_ports"`
	TopRejectedSrcIPs []chartPoint             `json:"top_rejected_src_ips"`
	TopInterfaces     []chartPoint             `json:"top_interfaces"`
	TopTalkersByBytes []chartPoint             `json:"top_talkers_by_bytes"`
	TopConversations  []conversation           `json:"top_conversations"`
	InternalExternal  []internalExternalBucket `json:"internal_external_split"`
	BurstWindows      []burstWindow            `json:"burst_windows"`
}

type findingRecord struct {
	Type        string
	Severity    string
	Title       string
	Description string
	FirstSeenAt *time.Time
	LastSeenAt  *time.Time
	Count       int
	Metadata    map[string]any
}

type processedEvent struct {
	UploadID    int64
	Version     int
	AccountID   string
	InterfaceID string
	SrcAddr     string
	DstAddr     string
	SrcPort     *int
	DstPort     *int
	Protocol    *int
	Packets     *int64
	Bytes       *int64
	StartTime   *time.Time
	EndTime     *time.Time
	Action      string
	LogStatus   string
	RawLine     string
}

type analysisAccumulator struct {
	totalLines            int
	parsedLines           int
	parseErrors           int
	acceptedCount         int
	rejectedCount         int
	noDataCount           int
	skipDataCount         int
	srcCounts             map[string]int64
	dstPortCounts         map[string]int64
	rejectedSrcCounts     map[string]int64
	interfaceCounts       map[string]int64
	bytesBySrc            map[string]int64
	conversations         map[string]*conversation
	internalExternalFlows map[string]int64
	internalExternalBytes map[string]int64
	burstBuckets          map[int64]int64
}

type findingsAggregator struct {
	rejectedBySrc        map[string]int
	bytesBySrc           map[string]int64
	sensitiveByKey       map[string]int
	sshBySrc             map[string]*sshAttemptStats
	suspiciousProbeByKey map[string]*probeStats
	firstSeenByKey       map[string]time.Time
	lastSeenByKey        map[string]time.Time
	scanWindows          map[string]*scanWindow
	timelineEntries      []timelineEntry
}

type scanWindow struct {
	SrcAddr   string
	Bucket    time.Time
	Ports     map[int]struct{}
	FlowCount int
	FirstSeen time.Time
	LastSeen  time.Time
}

type sshAttemptStats struct {
	Count         int
	RejectedCount int
	Targets       map[string]struct{}
}

type probeStats struct {
	Count   int
	Targets map[string]struct{}
}

type countPair struct {
	label string
	count int64
}
