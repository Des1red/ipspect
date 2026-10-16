package enrich

import (
	"fmt"
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/scanner/tcp/enrich/capture"
)

func enrichPort(
	hostIndex int,
	detailIndex int,
) {
	host := &models.LOOT.Hosts[hostIndex]
	detail := &host.Details[detailIndex]

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.enrich [%s:%d]: looking up IANA service",
			host.Target,
			detail.Port,
		),
	)

	detail.DBLookup = load.LookupPort(
		detail.Port,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.enrich [%s:%d]: IANA result=%q",
			host.Target,
			detail.Port,
			detail.DBLookup,
		),
	)

	detail.Service = "unknown"

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.capture [%s:%d]: starting initial capture",
			host.Target,
			detail.Port,
		),
	)

	capture.Capture(
		host.Target,
		detail,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.capture [%s:%d]: banner=%q raw_bytes=%d headers=%d",
			host.Target,
			detail.Port,
			detail.Banner,
			len(detail.RawResponse),
			len(detail.Headers),
		),
	)
}
