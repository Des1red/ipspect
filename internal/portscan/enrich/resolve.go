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

	detail.Service = "unknown"

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

		if detail.DBLookup != "" &&
			detail.DBLookup != "unknown" {

			detail.ServiceReason = fmt.Sprintf(
				"Fingerprint overrides IANA %q (%s)",
				detail.DBLookup,
				fp.Evidence,
			)

			return
		}

		detail.ServiceReason = fmt.Sprintf(
			"Fingerprint identified service (%s)",
			fp.Evidence,
		)

		return
	}

	if detail.DBLookup != "" &&
		detail.DBLookup != "unknown" {

		detail.ServiceReason = fmt.Sprintf(
			"IANA suggests %q, but fingerprinting "+
				"could not confirm the service",
			detail.DBLookup,
		)

		return
	}

	detail.ServiceReason =
		"No IANA registration or confirmed fingerprint"
}
