package main

import "net"

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

const (
	logTypeVPC               = "vpc_flow"
	findingRejectedTraffic   = "REJECTED_TRAFFIC"
	findingHighPortScan      = "HIGH_PORT_SCAN"
	findingSensitivePort     = "SENSITIVE_PORT_TRAFFIC"
	findingSSHBruteForce     = "SSH_BRUTE_FORCE"
	findingSuspiciousProbe   = "SUSPICIOUS_PORT_PROBE"
	actionAccept             = "ACCEPT"
	actionReject             = "REJECT"
	logStatusOK              = "OK"
	logStatusNoData          = "NODATA"
	logStatusSkipData        = "SKIPDATA"
	rejectedTrafficThreshold = 3
	sensitivePortThreshold   = 3
	sshBruteForceThreshold   = 10
	suspiciousProbeThreshold = 5
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

var suspiciousProbePorts = map[int]struct{}{
	21:   {},
	22:   {},
	23:   {},
	445:  {},
	1433: {},
	3389: {},
	5900: {},
	6379: {},
}

var portServiceNames = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	445:  "SMB",
	1433: "MSSQL",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	6379: "Redis",
}
