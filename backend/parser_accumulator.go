package main

import "strconv"

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
