package main

import (
	"strconv"
	"strings"
	"time"
)

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
