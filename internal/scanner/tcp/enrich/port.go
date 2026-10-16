package enrich

import (
	"ipspect/internal/analyzer"
	"ipspect/internal/models"
	"ipspect/internal/scanner/tcp/enrich/capture"
)

func enrichPort(
	hostIndex int,
	detailIndex int,
) {
	host := &models.LOOT.Hosts[hostIndex]
	detail := &host.Details[detailIndex]

	engine := analyzer.New()

	detail.DBLookup = engine.LookupPort(
		detail.Port,
	)

	detail.Service = "unknown"

	capture.Capture(
		host.Target,
		detail,
	)
}
