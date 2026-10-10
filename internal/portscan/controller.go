package portscan

import (
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/portscan/arp"
	"ipspect/internal/portscan/enrich"
	"ipspect/internal/portscan/ping"
	"ipspect/internal/portscan/search"
	"sort"
)

func Run() {
	if err := ping.Controller(); err != nil {
		output.Log(
			"error",
			"failed to initialize ICMP scanner: "+
				err.Error(),
		)
	}

	output.Log("icmp", "")

	if err := arp.Controller(); err != nil {
		output.Log(
			"error",
			"ARP discovery failed: "+
				err.Error(),
		)
	}

	output.Log("arp", "")

	search.Controller()

	sortPorts()
	output.Log("ports", "")

	if hasOpenPorts() {
		enrich.Controller()
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

func sortPorts() {
	for i := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[i]

		sort.Ints(host.Ports)
		sort.Ints(host.Closed)
		sort.Ints(host.Filtered)

		sort.Slice(host.Details, func(i, j int) bool {
			return host.Details[i].Port < host.Details[j].Port
		})
	}
}
