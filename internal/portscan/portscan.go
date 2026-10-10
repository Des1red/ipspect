package portscan

import (
	"ipspect/internal/output"
)

func Ping() {
	ping()

	output.Log("icmp", "")
}

func Ports() {
	portScan()
}
