package flow

import (
	"ipspect/internal/analyzer"
	"ipspect/internal/models"
	"ipspect/internal/scanner/tcp/enrich/fingerprint/sender"
)

func probeProtocols(
	ip string,
	detail *models.PortDetail,
	engine *analyzer.Engine,
) bool {
	// Prioritize DNS on its registered port.
	if detail.DBLookup == "domain" {
		dns := sender.ProbeDNS(
			ip,
			detail.Port,
			engine,
		)

		if dns.Service != "" {
			engine.RecordMatches(
				detail,
				[]models.FingerprintMatch{dns},
			)

			return true
		}
	}

	matches := make(
		[]models.FingerprintMatch,
		0,
		2,
	)

	http := sender.ProbeHTTP(
		ip,
		detail.Port,
		false,
		engine,
	)

	if http.Service != "" {
		matches = append(matches, http)
	}

	https := sender.ProbeHTTP(
		ip,
		detail.Port,
		true,
		engine,
	)

	if https.Service != "" {
		matches = append(matches, https)
	}

	if len(matches) > 0 {
		engine.RecordMatches(
			detail,
			matches,
		)

		return true
	}

	// Check DNS on nonstandard ports.
	if detail.DBLookup != "domain" {
		dns := sender.ProbeDNS(
			ip,
			detail.Port,
			engine,
		)

		if dns.Service != "" {
			engine.RecordMatches(
				detail,
				[]models.FingerprintMatch{dns},
			)

			return true
		}
	}

	return false
}
