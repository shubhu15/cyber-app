package main

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

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

func isExternalIP(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && !isInternalIP(value)
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

func serviceNameForPort(port int) string {
	if service, ok := portServiceNames[port]; ok {
		return service
	}
	return "unknown"
}
