package enrich

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/capture"
)

func enrichPort(
	hostIndex int,
	detailIndex int,
) {
	host := &models.LOOT.Hosts[hostIndex]
	detail := &host.Details[detailIndex]

	detail.DBLookup = load.LookupPort(
		detail.Port,
	)

	detail.Service = "unknown"

	capture.Capture(
		host.Target,
		detail,
	)
}
