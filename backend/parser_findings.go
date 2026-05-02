package main

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

func newFindingsAggregator() *findingsAggregator {
	return &findingsAggregator{
		rejectedBySrc:        make(map[string]int),
		bytesBySrc:           make(map[string]int64),
		sensitiveByKey:       make(map[string]int),
		sshBySrc:             make(map[string]*sshAttemptStats),
		suspiciousProbeByKey: make(map[string]*probeStats),
		firstSeenByKey:       make(map[string]time.Time),
		lastSeenByKey:        make(map[string]time.Time),
		scanWindows:          make(map[string]*scanWindow),
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

	if parsed.SrcAddr != "" && parsed.DstAddr != "" && parsed.DstPort != nil && *parsed.DstPort == 22 && isExternalIP(parsed.SrcAddr) {
		stats := f.sshBySrc[parsed.SrcAddr]
		if stats == nil {
			stats = &sshAttemptStats{Targets: make(map[string]struct{})}
			f.sshBySrc[parsed.SrcAddr] = stats
		}
		stats.Count++
		if parsed.Action == actionReject {
			stats.RejectedCount++
		}
		stats.Targets[parsed.DstAddr] = struct{}{}
		f.touch(findingSSHBruteForce+"|"+parsed.SrcAddr, parsed.StartTime)
	}

	if parsed.Action == actionReject && parsed.SrcAddr != "" && parsed.DstPort != nil {
		if _, ok := suspiciousProbePorts[*parsed.DstPort]; ok {
			key := parsed.SrcAddr + "|" + strconv.Itoa(*parsed.DstPort)
			stats := f.suspiciousProbeByKey[key]
			if stats == nil {
				stats = &probeStats{Targets: make(map[string]struct{})}
				f.suspiciousProbeByKey[key] = stats
			}
			stats.Count++
			if parsed.DstAddr != "" {
				stats.Targets[parsed.DstAddr] = struct{}{}
			}
			f.touch(findingSuspiciousProbe+"|"+key, parsed.StartTime)
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

	for src, stats := range f.sshBySrc {
		if stats.Count < sshBruteForceThreshold {
			continue
		}
		firstSeen := f.timeForKey(findingSSHBruteForce + "|" + src)
		lastSeen := f.lastTimeForKey(findingSSHBruteForce + "|" + src)
		findings = append(findings, findingRecord{
			Type:        findingSSHBruteForce,
			Severity:    "high",
			Title:       "SSH brute-force candidate",
			Description: src + " generated repeated SSH attempts against internal targets.",
			FirstSeenAt: firstSeen,
			LastSeenAt:  lastSeen,
			Count:       stats.Count,
			Metadata: map[string]any{
				"src_addr":       src,
				"dst_port":       22,
				"service":        serviceNameForPort(22),
				"target_count":   len(stats.Targets),
				"rejected_count": stats.RejectedCount,
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
				"service":  serviceNameForPort(port),
			},
		})
	}

	for key, stats := range f.suspiciousProbeByKey {
		if stats.Count < suspiciousProbeThreshold {
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
		firstSeen := f.timeForKey(findingSuspiciousProbe + "|" + key)
		lastSeen := f.lastTimeForKey(findingSuspiciousProbe + "|" + key)
		findings = append(findings, findingRecord{
			Type:        findingSuspiciousProbe,
			Severity:    "medium",
			Title:       "Repeated suspicious port probes",
			Description: parts[0] + " generated repeated rejected probes to " + serviceNameForPort(port) + " port " + parts[1] + ".",
			FirstSeenAt: firstSeen,
			LastSeenAt:  lastSeen,
			Count:       stats.Count,
			Metadata: map[string]any{
				"src_addr":       parts[0],
				"dst_port":       port,
				"service":        serviceNameForPort(port),
				"target_count":   len(stats.Targets),
				"rejected_count": stats.Count,
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
