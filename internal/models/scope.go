package models

import (
	"net"
	"time"
)

type TargetRange struct {
	Multi  bool
	Single bool
}

var TR TargetRange

var INFO struct {
	TargetName string
	Targets    []net.IP

	PortStart int
	PortEnd   int

	Ports    []int
	PortSpec string
}

type PortDetail struct {
	Port    int
	State   string
	Service string
	Banner  string
	Headers map[string][]string
	Latency time.Duration

	DBLookup      string
	Fingerprint   FingerprintResult
	ServiceReason string
}

type FingerprintResult struct {
	Service    string
	Product    string
	Confidence string
	Evidence   string

	Matches []FingerprintMatch
}

type FingerprintMatch struct {
	Service  string
	Product  string
	Evidence string

	Banner  string
	Headers map[string][]string
}

type HostResult struct {
	Target string

	Ports    []int
	Closed   []int
	Filtered []int

	ClosedCount   int
	FilteredCount int

	Details []PortDetail
}

var LOOT struct {
	ICMPReachable []string
	ARPReachable  []string
	ARPResults    []ARPResult
	Hosts         []HostResult
}

type ARPResult struct {
	IP        string
	MAC       string
	Vendor    string
	Interface string

	Hostname    string
	PTRName     string
	NetBIOSName string
}
