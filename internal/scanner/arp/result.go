package arp

import (
	"bytes"
	"ipspect/internal/models"
	"sort"
)

func storeResults(
	found map[string]arpHost,
) {
	hosts := make(
		[]arpHost,
		0,
		len(found),
	)

	for _, host := range found {
		hosts = append(
			hosts,
			host,
		)
	}

	sort.Slice(
		hosts,
		func(i, j int) bool {
			return bytes.Compare(
				hosts[i].ip.To4(),
				hosts[j].ip.To4(),
			) < 0
		},
	)

	models.LOOT.ARPReachable = make(
		[]string,
		0,
		len(hosts),
	)

	models.LOOT.ARPResults = make(
		[]models.ARPResult,
		0,
		len(hosts),
	)

	for _, host := range hosts {
		ip := host.ip.String()

		models.LOOT.ARPReachable = append(
			models.LOOT.ARPReachable,
			ip,
		)

		models.LOOT.ARPResults = append(
			models.LOOT.ARPResults,
			models.ARPResult{
				IP:        ip,
				MAC:       host.mac.String(),
				Interface: host.iface,
			},
		)
	}
}
