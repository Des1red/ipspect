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

		registered := false

		for _, match := range fp.Matches {
			if sameService(
				detail.DBLookup,
				match.Service,
			) {
				registered = true
				break
			}
		}

		if len(fp.Matches) > 1 {
			if registered {
				detail.ServiceReason = fmt.Sprintf(
					"IANA %q confirmed; additional protocol(s) detected (%s)",
					detail.DBLookup,
					fp.Evidence,
				)
			} else {
				detail.ServiceReason = fmt.Sprintf(
					"Multiple protocols confirmed; IANA %q is only a registration (%s)",
					detail.DBLookup,
					fp.Evidence,
				)
			}

			return
		}

		if registered {
			detail.ServiceReason = fmt.Sprintf(
				"Fingerprint confirmed IANA (%s)",
				fp.Evidence,
			)
		} else if detail.DBLookup != "" &&
			detail.DBLookup != "unknown" {

			detail.ServiceReason = fmt.Sprintf(
				"Fingerprint overrides IANA %q (%s)",
				detail.DBLookup,
				fp.Evidence,
			)
		} else {
			detail.ServiceReason = fmt.Sprintf(
				"Fingerprint identified service (%s)",
				fp.Evidence,
			)
		}

		return
	}

	if detail.DBLookup != "" &&
		detail.DBLookup != "unknown" {

		detail.ServiceReason = fmt.Sprintf(
			"IANA suggests %q, but fingerprinting could not confirm the service",
			detail.DBLookup,
		)

		return
	}

	detail.ServiceReason =
		"No IANA registration or confirmed fingerprint"
}
