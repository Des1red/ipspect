package portscan

import (
	"ipspect/internal/models"
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
