package models

import "time"

type PortDetail struct {
	Port    int
	State   string
	Service string
	Banner  string
	Headers map[string][]string
	Latency time.Duration

	DBLookup      string
	Fingerprint   FingerprintResult
	RawResponse   []byte
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

	Banner     string
	Headers    map[string][]string
	Confidence string
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

type ARPResult struct {
	IP        string
	MAC       string
	Vendor    string
	Interface string

	Hostname    string
	PTRName     string
	NetBIOSName string
}

var LOOT struct {
	ICMPReachable []string
	ARPReachable  []string
	ARPResults    []ARPResult
	Hosts         []HostResult
}
