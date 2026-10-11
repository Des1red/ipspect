package enrich

import (
	"fmt"
	"ipspect/internal/models"
)

func resolveServices() {
	for h := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[h]

		for i := range host.Details {
			detail := &host.Details[i]

			if detail.State != "open" {
				continue
			}

			resolveService(detail)
		}
	}
}

func resolveService(
	detail *models.PortDetail,
) {
	fp := detail.Fingerprint

	if fp.Service != "" &&
		fp.Confidence == "high" {

		detail.Service = fp.Service

		if detail.DBLookup == fp.Service {
			detail.ServiceReason = fmt.Sprintf(
				"Fingerprint confirmed IANA (%s)",
				fp.Evidence,
			)

			return
		}

		detail.ServiceReason = fmt.Sprintf(
			"Fingerprint overrides IANA %q (%s)",
			detail.DBLookup,
			fp.Evidence,
		)

		return
	}

	if detail.DBLookup != "" &&
		detail.DBLookup != "unknown" {

		detail.Service = detail.DBLookup

		detail.ServiceReason =
			"IANA fallback; service not fingerprint-verified"

		return
	}

	detail.Service = "unknown"

	detail.ServiceReason =
		"No IANA registration or confirmed fingerprint"
}
