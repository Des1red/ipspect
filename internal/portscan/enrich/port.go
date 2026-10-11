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

	detail.Service = detail.DBLookup

	switch detail.Port {
	case 80, 8080:
		enrichHTTP(
			host.Target,
			detail,
			"http",
		)

	case 443:
		enrichHTTP(
			host.Target,
			detail,
			"https",
		)

	default:
		enrichTCP(
			host.Target,
			detail,
		)
	}
}
