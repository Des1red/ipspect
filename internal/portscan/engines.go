package portscan

import (
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/portscan/arp"
	"ipspect/internal/portscan/ping"
	"ipspect/internal/portscan/tcp/enrich"
	"ipspect/internal/portscan/tcp/search"
	"sort"
)

func runICMP(
	stages *stageCounter,
) {
	stages.next("ICMP Discovery")

	if err := ping.Controller(); err != nil {
		output.Log(
			"error",
			"failed to initialize ICMP scanner: "+
				err.Error(),
		)
	}

	output.Log("icmp", "")
}

func runARP(
	stages *stageCounter,
) {
	stages.next("ARP Discovery")

	if err := arp.Controller(); err != nil {
		output.Log(
			"error",
			"ARP stage: "+err.Error(),
		)
	}

	output.Log("arp", "")
}

func runTCP(
	stages *stageCounter,
) {
	prioritizeTargets()

	stages.next("TCP SYN Scanning")

	search.Controller()

	sortPorts()
	output.Log("ports", "")

	stages.next("Service Identification")

	runIdentification()

	stages.next("Scan Results")

	output.Log("result", "")
}

func runIdentification() {
	if !hasOpenPorts() {
		output.Log(
			"warning",
			"No open ports; skipping service identification",
		)

		return
	}

	if err := enrich.Controller(); err != nil {
		output.Log(
			"error",
			"service enrichment failed: "+
				err.Error(),
		)
	}

	output.Log("identification", "")
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

		sort.Slice(
			host.Details,
			func(i, j int) bool {
				return host.Details[i].Port <
					host.Details[j].Port
			},
		)
	}
}
