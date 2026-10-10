package enrich

import (
	"ipspect/internal/models"
)

func enrichPort(
	hostIndex int,
	detailIndex int,
) {
	host := &models.LOOT.Hosts[hostIndex]
	detail := &host.Details[detailIndex]

	service := lookupService(
		detail.Port,
	)

	detail.Service = service

	switch service {
	case "http",
		"http-proxy",
		"https":

		enrichHTTP(
			host.Target,
			detail,
			service,
		)

	default:
		enrichTCP(
			host.Target,
			detail,
		)
	}
}
