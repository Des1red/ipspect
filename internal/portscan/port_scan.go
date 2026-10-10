package portscan

import (
	"ipspect/internal/models"
	"ipspect/internal/output"
	"sort"
)

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

func portScan() (bool, bool) {
	port_search()

	sortPorts()

	foundOpen := false
	foundFiltered := false

	for _, host := range models.LOOT.Hosts {
		if len(host.Ports) > 0 {
			foundOpen = true
		}

		if host.FilteredCount > 0 {
			foundFiltered = true
		}
	}

	output.Log("ports", "")

	if foundOpen {
		enrich()
	}

	return foundOpen, foundFiltered
}
