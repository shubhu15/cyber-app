package main

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	burstBucketSeconds = 300

	bucketInternalToInternal = "internal_to_internal"
	bucketInternalToExternal = "internal_to_external"
	bucketExternalToInternal = "external_to_internal"
	bucketExternalToExternal = "external_to_external"
)

var rfc1918Networks = func() []*net.IPNet {
	cidrs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		nets = append(nets, network)
	}
	return nets
}()

func isInternalIP(value string) bool {
	if value == "" {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	for _, network := range rfc1918Networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

const (
	logTypeVPC               = "vpc_flow"
	findingRejectedTraffic   = "REJECTED_TRAFFIC"
	findingHighPortScan      = "HIGH_PORT_SCAN"
	findingSensitivePort     = "SENSITIVE_PORT_TRAFFIC"
	actionAccept             = "ACCEPT"
	actionReject             = "REJECT"
	logStatusOK              = "OK"
	logStatusNoData          = "NODATA"
	logStatusSkipData        = "SKIPDATA"
	rejectedTrafficThreshold = 3
	sensitivePortThreshold   = 3
	portScanPortThreshold    = 10
	portScanFlowThreshold    = 10
	topNLimit                = 5
)

var sensitivePorts = map[int]struct{}{
	22:   {},
	3389: {},
	445:  {},
	1433: {},
	3306: {},
	5432: {},
}

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
	totalLines             int
	parsedLines            int
	parseErrors            int
	acceptedCount          int
	rejectedCount          int
	noDataCount            int
	skipDataCount          int
	srcCounts              map[string]int64
	dstPortCounts          map[string]int64
	rejectedSrcCounts      map[string]int64
	interfaceCounts        map[string]int64
	bytesBySrc             map[string]int64
	conversations          map[string]*conversation
	internalExternalFlows  map[string]int64
	internalExternalBytes  map[string]int64
	burstBuckets           map[int64]int64
}

type findingsAggregator struct {
	rejectedBySrc   map[string]int
	bytesBySrc      map[string]int64
	sensitiveByKey  map[string]int
	firstSeenByKey  map[string]time.Time
	lastSeenByKey   map[string]time.Time
	scanWindows     map[string]*scanWindow
	timelineEntries []timelineEntry
}

type scanWindow struct {
	SrcAddr   string
	Bucket    time.Time
	Ports     map[int]struct{}
	FlowCount int
	FirstSeen time.Time
	LastSeen  time.Time
}

type countPair struct {
	label string
	count int64
}

func newAnalysisAccumulator() *analysisAccumulator {
	return &analysisAccumulator{
		srcCounts:             make(map[string]int64),
		dstPortCounts:         make(map[string]int64),
		rejectedSrcCounts:     make(map[string]int64),
		interfaceCounts:       make(map[string]int64),
		bytesBySrc:            make(map[string]int64),
		conversations:         make(map[string]*conversation),
		internalExternalFlows: make(map[string]int64),
		internalExternalBytes: make(map[string]int64),
		burstBuckets:          make(map[int64]int64),
	}
}

func newFindingsAggregator() *findingsAggregator {
	return &findingsAggregator{
		rejectedBySrc:  make(map[string]int),
		bytesBySrc:     make(map[string]int64),
		sensitiveByKey: make(map[string]int),
		firstSeenByKey: make(map[string]time.Time),
		lastSeenByKey:  make(map[string]time.Time),
		scanWindows:    make(map[string]*scanWindow),
	}
}

func parseVpcFlowLine(line string) (*parsedVpcFlowLine, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 14 {
		return nil, false
	}

	version, ok := parseRequiredInt(fields[0])
	if !ok {
		return nil, false
	}

	srcPort, ok := parseOptionalInt(fields[5])
	if !ok {
		return nil, false
	}
	dstPort, ok := parseOptionalInt(fields[6])
	if !ok {
		return nil, false
	}
	protocol, ok := parseOptionalInt(fields[7])
	if !ok {
		return nil, false
	}
	packets, ok := parseOptionalInt64(fields[8])
	if !ok {
		return nil, false
	}
	bytesValue, ok := parseOptionalInt64(fields[9])
	if !ok {
		return nil, false
	}
	startTime, ok := parseOptionalUnixTime(fields[10])
	if !ok {
		return nil, false
	}
	endTime, ok := parseOptionalUnixTime(fields[11])
	if !ok {
		return nil, false
	}

	action := strings.ToUpper(strings.TrimSpace(fields[12]))
	if action != actionAccept && action != actionReject && action != "-" {
		return nil, false
	}

	logStatus := strings.ToUpper(strings.TrimSpace(fields[13]))
	switch logStatus {
	case logStatusOK, logStatusNoData, logStatusSkipData:
	default:
		return nil, false
	}

	return &parsedVpcFlowLine{
		Version:     version,
		AccountID:   normalizeField(fields[1]),
		InterfaceID: normalizeField(fields[2]),
		SrcAddr:     normalizeField(fields[3]),
		DstAddr:     normalizeField(fields[4]),
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    protocol,
		Packets:     packets,
		Bytes:       bytesValue,
		StartTime:   startTime,
		EndTime:     endTime,
		Action:      action,
		LogStatus:   logStatus,
	}, true
}

func parseRequiredInt(value string) (int, bool) {
	clean := strings.TrimSpace(value)
	if clean == "" || clean == "-" {
		return 0, false
	}
	parsed, err := strconv.Atoi(clean)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func parseOptionalInt(value string) (*int, bool) {
	clean := strings.TrimSpace(value)
	if clean == "" || clean == "-" {
		return nil, true
	}
	parsed, err := strconv.Atoi(clean)
	if err != nil {
		return nil, false
	}
	return &parsed, true
}

func parseOptionalInt64(value string) (*int64, bool) {
	clean := strings.TrimSpace(value)
	if clean == "" || clean == "-" {
		return nil, true
	}
	parsed, err := strconv.ParseInt(clean, 10, 64)
	if err != nil {
		return nil, false
	}
	return &parsed, true
}

func parseOptionalUnixTime(value string) (*time.Time, bool) {
	clean := strings.TrimSpace(value)
	if clean == "" || clean == "-" {
		return nil, true
	}
	parsed, err := strconv.ParseInt(clean, 10, 64)
	if err != nil {
		return nil, false
	}
	timestamp := time.Unix(parsed, 0).UTC()
	return &timestamp, true
}

func normalizeField(value string) string {
	clean := strings.TrimSpace(value)
	if clean == "-" {
		return ""
	}
	return clean
}

func (a *analysisAccumulator) addLine() {
	a.totalLines++
}

func (a *analysisAccumulator) addParseError() {
	a.parseErrors++
}

func (a *analysisAccumulator) addEvent(parsed *parsedVpcFlowLine) {
	a.parsedLines++
	if parsed.Action == actionAccept {
		a.acceptedCount++
	}
	if parsed.Action == actionReject {
		a.rejectedCount++
	}
	switch parsed.LogStatus {
	case logStatusNoData:
		a.noDataCount++
	case logStatusSkipData:
		a.skipDataCount++
	}
	if parsed.SrcAddr != "" {
		a.srcCounts[parsed.SrcAddr]++
	}
	if parsed.DstPort != nil {
		a.dstPortCounts[strconv.Itoa(*parsed.DstPort)]++
	}
	if parsed.Action == actionReject && parsed.SrcAddr != "" {
		a.rejectedSrcCounts[parsed.SrcAddr]++
	}
	if parsed.InterfaceID != "" {
		a.interfaceCounts[parsed.InterfaceID]++
	}
	if parsed.SrcAddr != "" && parsed.Bytes != nil {
		a.bytesBySrc[parsed.SrcAddr] += *parsed.Bytes
	}
	if parsed.SrcAddr != "" && parsed.DstAddr != "" {
		key := parsed.SrcAddr + "|" + parsed.DstAddr + "|"
		dstPort := -1
		if parsed.DstPort != nil {
			dstPort = *parsed.DstPort
			key += strconv.Itoa(dstPort)
		}
		convo, exists := a.conversations[key]
		if !exists {
			convo = &conversation{
				SrcAddr: parsed.SrcAddr,
				DstAddr: parsed.DstAddr,
			}
			if parsed.DstPort != nil {
				port := *parsed.DstPort
				convo.DstPort = &port
			}
			a.conversations[key] = convo
		}
		convo.Flows++
		if parsed.Bytes != nil {
			convo.Bytes += *parsed.Bytes
		}
	}
	if parsed.SrcAddr != "" && parsed.DstAddr != "" {
		bucket := internalExternalBucketKey(parsed.SrcAddr, parsed.DstAddr)
		a.internalExternalFlows[bucket]++
		if parsed.Bytes != nil {
			a.internalExternalBytes[bucket] += *parsed.Bytes
		}
	}
	if parsed.StartTime != nil {
		bucketEpoch := parsed.StartTime.UTC().Unix() / burstBucketSeconds * burstBucketSeconds
		a.burstBuckets[bucketEpoch]++
	}
}

func internalExternalBucketKey(srcAddr, dstAddr string) string {
	srcInternal := isInternalIP(srcAddr)
	dstInternal := isInternalIP(dstAddr)
	switch {
	case srcInternal && dstInternal:
		return bucketInternalToInternal
	case srcInternal && !dstInternal:
		return bucketInternalToExternal
	case !srcInternal && dstInternal:
		return bucketExternalToInternal
	default:
		return bucketExternalToExternal
	}
}

func (f *findingsAggregator) add(parsed *parsedVpcFlowLine) {
	if parsed.SrcAddr != "" && parsed.Bytes != nil {
		f.bytesBySrc[parsed.SrcAddr] += *parsed.Bytes
	}

	if parsed.Action == actionReject && parsed.SrcAddr != "" {
		f.rejectedBySrc[parsed.SrcAddr]++
		f.touch(findingRejectedTraffic+"|"+parsed.SrcAddr, parsed.StartTime)
	}

	if parsed.SrcAddr != "" && parsed.StartTime != nil && parsed.DstPort != nil {
		bucket := parsed.StartTime.UTC().Truncate(5 * time.Minute)
		key := parsed.SrcAddr + "|" + bucket.Format(time.RFC3339)
		window := f.scanWindows[key]
		if window == nil {
			window = &scanWindow{
				SrcAddr:   parsed.SrcAddr,
				Bucket:    bucket,
				Ports:     make(map[int]struct{}),
				FirstSeen: *parsed.StartTime,
				LastSeen:  *parsed.StartTime,
			}
			f.scanWindows[key] = window
		}
		window.FlowCount++
		window.Ports[*parsed.DstPort] = struct{}{}
		if parsed.StartTime.Before(window.FirstSeen) {
			window.FirstSeen = *parsed.StartTime
		}
		if parsed.StartTime.After(window.LastSeen) {
			window.LastSeen = *parsed.StartTime
		}
	}

	if parsed.SrcAddr != "" && parsed.DstPort != nil {
		if _, ok := sensitivePorts[*parsed.DstPort]; ok {
			key := parsed.SrcAddr + "|" + strconv.Itoa(*parsed.DstPort)
			f.sensitiveByKey[key]++
			f.touch(findingSensitivePort+"|"+key, parsed.StartTime)
		}
	}
}

func (f *findingsAggregator) build() []findingRecord {
	findings := make([]findingRecord, 0)

	for src, count := range f.rejectedBySrc {
		if count < rejectedTrafficThreshold {
			continue
		}
		firstSeen := f.timeForKey(findingRejectedTraffic + "|" + src)
		lastSeen := f.lastTimeForKey(findingRejectedTraffic + "|" + src)
		findings = append(findings, findingRecord{
			Type:        findingRejectedTraffic,
			Severity:    "medium",
			Title:       "Repeated rejected traffic from source",
			Description: src + " generated repeated rejected VPC flows.",
			FirstSeenAt: firstSeen,
			LastSeenAt:  lastSeen,
			Count:       count,
			Metadata: map[string]any{
				"src_addr": src,
			},
		})
	}

	for _, window := range f.scanWindows {
		if len(window.Ports) < portScanPortThreshold || window.FlowCount < portScanFlowThreshold {
			continue
		}
		portList := make([]int, 0, len(window.Ports))
		for port := range window.Ports {
			portList = append(portList, port)
		}
		sort.Ints(portList)
		findings = append(findings, findingRecord{
			Type:        findingHighPortScan,
			Severity:    "high",
			Title:       "High destination-port fanout detected",
			Description: window.SrcAddr + " targeted many destination ports in a short window.",
			FirstSeenAt: &window.FirstSeen,
			LastSeenAt:  &window.LastSeen,
			Count:       window.FlowCount,
			Metadata: map[string]any{
				"src_addr":      window.SrcAddr,
				"unique_ports":  len(window.Ports),
				"ports_sample":  portList,
				"window_bucket": window.Bucket.Format(time.RFC3339),
			},
		})
	}

	for key, count := range f.sensitiveByKey {
		if count < sensitivePortThreshold {
			continue
		}
		parts := strings.Split(key, "|")
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		firstSeen := f.timeForKey(findingSensitivePort + "|" + key)
		lastSeen := f.lastTimeForKey(findingSensitivePort + "|" + key)
		findings = append(findings, findingRecord{
			Type:        findingSensitivePort,
			Severity:    "medium",
			Title:       "Repeated traffic to a sensitive port",
			Description: parts[0] + " repeatedly targeted sensitive port " + parts[1] + ".",
			FirstSeenAt: firstSeen,
			LastSeenAt:  lastSeen,
			Count:       count,
			Metadata: map[string]any{
				"src_addr": parts[0],
				"dst_port": port,
			},
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findingSeverityRank(findings[i].Severity) == findingSeverityRank(findings[j].Severity) {
			if findings[i].Type == findings[j].Type {
				return findings[i].Count > findings[j].Count
			}
			return findings[i].Type < findings[j].Type
		}
		return findingSeverityRank(findings[i].Severity) > findingSeverityRank(findings[j].Severity)
	})

	f.timelineEntries = buildTimelineEntries(findings)
	return findings
}

func (f *findingsAggregator) timeline() []timelineEntry {
	if f.timelineEntries == nil {
		return []timelineEntry{}
	}
	return f.timelineEntries
}

func (f *findingsAggregator) touch(key string, ts *time.Time) {
	if ts == nil {
		return
	}
	if _, exists := f.firstSeenByKey[key]; !exists {
		f.firstSeenByKey[key] = *ts
	}
	f.lastSeenByKey[key] = *ts
}

func (f *findingsAggregator) timeForKey(key string) *time.Time {
	value, ok := f.firstSeenByKey[key]
	if !ok {
		return nil
	}
	copyValue := value
	return &copyValue
}

func (f *findingsAggregator) lastTimeForKey(key string) *time.Time {
	value, ok := f.lastSeenByKey[key]
	if !ok {
		return nil
	}
	copyValue := value
	return &copyValue
}

func buildTimelineEntries(findings []findingRecord) []timelineEntry {
	type accum struct {
		severity      string
		title         string
		first         *time.Time
		last          *time.Time
		instanceCount int
		totalCount    int
	}
	byType := make(map[string]*accum)
	order := make([]string, 0)

	for _, finding := range findings {
		entry, exists := byType[finding.Type]
		if !exists {
			entry = &accum{severity: finding.Severity, title: finding.Title}
			byType[finding.Type] = entry
			order = append(order, finding.Type)
		}
		entry.instanceCount++
		entry.totalCount += finding.Count
		if finding.FirstSeenAt != nil {
			if entry.first == nil || finding.FirstSeenAt.Before(*entry.first) {
				value := *finding.FirstSeenAt
				entry.first = &value
			}
		}
		if finding.LastSeenAt != nil {
			if entry.last == nil || finding.LastSeenAt.After(*entry.last) {
				value := *finding.LastSeenAt
				entry.last = &value
			}
		}
	}

	entries := make([]timelineEntry, 0, len(order))
	for _, typeKey := range order {
		entry := byType[typeKey]
		first := ""
		last := ""
		if entry.first != nil {
			first = entry.first.UTC().Format(time.RFC3339)
		}
		if entry.last != nil {
			last = entry.last.UTC().Format(time.RFC3339)
		}
		entries = append(entries, timelineEntry{
			Type:          typeKey,
			Severity:      entry.severity,
			Title:         entry.title,
			FirstSeenAt:   first,
			LastSeenAt:    last,
			InstanceCount: entry.instanceCount,
			TotalCount:    entry.totalCount,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if findingSeverityRank(entries[i].Severity) == findingSeverityRank(entries[j].Severity) {
			return entries[i].FirstSeenAt < entries[j].FirstSeenAt
		}
		return findingSeverityRank(entries[i].Severity) > findingSeverityRank(entries[j].Severity)
	})

	return entries
}

func buildCharts(acc *analysisAccumulator) chartData {
	conversations := make([]conversation, 0, len(acc.conversations))
	for _, convo := range acc.conversations {
		conversations = append(conversations, *convo)
	}
	sort.Slice(conversations, func(i, j int) bool {
		if conversations[i].Bytes == conversations[j].Bytes {
			if conversations[i].SrcAddr == conversations[j].SrcAddr {
				return conversations[i].DstAddr < conversations[j].DstAddr
			}
			return conversations[i].SrcAddr < conversations[j].SrcAddr
		}
		return conversations[i].Bytes > conversations[j].Bytes
	})
	if len(conversations) > topNLimit {
		conversations = conversations[:topNLimit]
	}

	bucketOrder := []string{
		bucketInternalToInternal,
		bucketInternalToExternal,
		bucketExternalToInternal,
		bucketExternalToExternal,
	}
	internalExternal := make([]internalExternalBucket, 0, len(bucketOrder))
	for _, key := range bucketOrder {
		internalExternal = append(internalExternal, internalExternalBucket{
			Bucket: key,
			Flows:  acc.internalExternalFlows[key],
			Bytes:  acc.internalExternalBytes[key],
		})
	}

	burstWindows := make([]burstWindow, 0, len(acc.burstBuckets))
	for epoch, count := range acc.burstBuckets {
		burstWindows = append(burstWindows, burstWindow{
			Bucket: time.Unix(epoch, 0).UTC().Format(time.RFC3339),
			Count:  count,
		})
	}
	sort.Slice(burstWindows, func(i, j int) bool {
		if burstWindows[i].Count == burstWindows[j].Count {
			return burstWindows[i].Bucket < burstWindows[j].Bucket
		}
		return burstWindows[i].Count > burstWindows[j].Count
	})
	if len(burstWindows) > topNLimit {
		burstWindows = burstWindows[:topNLimit]
	}

	return chartData{
		TopSrcIPs:         toChartPoints(topCountPairs(acc.srcCounts, topNLimit)),
		TopDstPorts:       toChartPoints(topCountPairs(acc.dstPortCounts, topNLimit)),
		TopRejectedSrcIPs: toChartPoints(topCountPairs(acc.rejectedSrcCounts, topNLimit)),
		TopInterfaces:     toChartPoints(topCountPairs(acc.interfaceCounts, topNLimit)),
		TopTalkersByBytes: toChartPoints(topCountPairs(acc.bytesBySrc, topNLimit)),
		TopConversations:  conversations,
		InternalExternal:  internalExternal,
		BurstWindows:      burstWindows,
	}
}

func buildAISummary(acc *analysisAccumulator, findings []findingRecord) string {
	parts := []string{
		"Processed " + strconv.Itoa(acc.parsedLines) + " VPC flow records",
		"with " + strconv.Itoa(acc.parseErrors) + " parse errors.",
		strconv.Itoa(acc.acceptedCount) + " were ACCEPT and " + strconv.Itoa(acc.rejectedCount) + " were REJECT.",
	}

	topSources := topCountPairs(acc.srcCounts, 3)
	if len(topSources) > 0 {
		parts = append(parts, "Top source IPs were "+joinCountPairs(topSources)+".")
	}

	topPorts := topCountPairs(acc.dstPortCounts, 3)
	if len(topPorts) > 0 {
		parts = append(parts, "Most targeted destination ports were "+joinCountPairs(topPorts)+".")
	}

	if len(findings) > 0 {
		parts = append(parts, "Highest-signal finding: "+strings.ToLower(findings[0].Title)+".")
	}

	return strings.Join(parts, " ")
}

func toJSON(value any) string {
	bytes, err := json.Marshal(value)
	if err != nil {
		return "[]"
	}
	return string(bytes)
}

func topCountPairs(source map[string]int64, limit int) []countPair {
	pairs := make([]countPair, 0, len(source))
	for label, count := range source {
		pairs = append(pairs, countPair{label: label, count: count})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].label < pairs[j].label
		}
		return pairs[i].count > pairs[j].count
	})

	if len(pairs) > limit {
		return pairs[:limit]
	}
	return pairs
}

func topCountPairsFromIntMap(source map[string]int, limit int) []countPair {
	pairs := make([]countPair, 0, len(source))
	for label, count := range source {
		pairs = append(pairs, countPair{label: label, count: int64(count)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].label < pairs[j].label
		}
		return pairs[i].count > pairs[j].count
	})
	if len(pairs) > limit {
		return pairs[:limit]
	}
	return pairs
}

func toChartPoints(pairs []countPair) []chartPoint {
	points := make([]chartPoint, 0, len(pairs))
	for _, pair := range pairs {
		points = append(points, chartPoint{
			Label: pair.label,
			Count: pair.count,
		})
	}
	return points
}

func joinCountPairs(pairs []countPair) string {
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		parts = append(parts, pair.label+" ("+strconv.FormatInt(pair.count, 10)+")")
	}
	return strings.Join(parts, ", ")
}

func findingSeverityRank(value string) int {
	switch value {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func protocolLabel(value *int) string {
	if value == nil {
		return "-"
	}
	switch *value {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return strconv.Itoa(*value)
	}
}
