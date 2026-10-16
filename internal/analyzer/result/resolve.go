package result

import (
	"fmt"
	"ipspect/internal/models"
)

func ResolveService(
	detail *models.PortDetail,
) {
	fp := detail.Fingerprint

	detail.Service = "unknown"

	// Confirmed fingerprint.
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

	// Tentative fingerprint.
	if fp.Service != "" {
		detail.ServiceReason = fmt.Sprintf(
			"Tentative %s identification (%s confidence): %s",
			fp.Service,
			fp.Confidence,
			fp.Evidence,
		)

		return
	}

	// Unknown response with captured evidence.
	if fp.Evidence != "" &&
		fp.Evidence != "No matching protocol signature" {

		if detail.DBLookup != "" &&
			detail.DBLookup != "unknown" {

			detail.ServiceReason = fmt.Sprintf(
				"IANA suggests %q (unconfirmed); %s",
				detail.DBLookup,
				fp.Evidence,
			)
		} else {
			detail.ServiceReason = fp.Evidence
		}

		return
	}

	// IANA registration without confirmation.
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
