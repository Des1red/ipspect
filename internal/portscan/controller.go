package portscan

import (
	"ipspect/internal/models"
	"ipspect/internal/output"
)

func Run() {
	ping()
	output.Log("icmp", "")

	port_search()

	sortPorts()
	output.Log("ports", "")

	if hasOpenPorts() {
		enrich()
	}

	output.Log("result", "")
}

func hasOpenPorts() bool {
	for _, host := range models.LOOT.Hosts {
		if len(host.Ports) > 0 {
			return true
		}
	}

	return false
}
