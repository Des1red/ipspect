package enrich

import "ipspect/internal/models"

func enrichPort(
	hostIndex int,
	detailIndex int,
) {
	host := &models.LOOT.Hosts[hostIndex]
	detail := &host.Details[detailIndex]

	detail.DBLookup = lookupService(
		detail.Port,
	)

	detail.Service = "unknown"

	enrichTCP(
		host.Target,
		detail,
	)
}
