package fingerprint

import (
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer/recog"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/sender"
)

func probeProtocols(
	ip string,
	detail *models.PortDetail,
	session *recog.Session,
) bool {
	// Prioritize DNS on its registered port.
	if detail.DBLookup == "domain" {
		dns := sender.ProbeDNS(
			ip,
			detail.Port,
		)

		if dns.Service != "" {
			analyzer.RecordMatches(
				detail,
				[]models.FingerprintMatch{dns},
				session,
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
	)

	if http.Service != "" {
		matches = append(matches, http)
	}

	https := sender.ProbeHTTP(
		ip,
		detail.Port,
		true,
	)

	if https.Service != "" {
		matches = append(matches, https)
	}

	if len(matches) > 0 {
		analyzer.RecordMatches(
			detail,
			matches,
			session,
		)

		return true
	}

	// Check DNS on nonstandard ports.
	if detail.DBLookup != "domain" {
		dns := sender.ProbeDNS(
			ip,
			detail.Port,
		)

		if dns.Service != "" {
			analyzer.RecordMatches(
				detail,
				[]models.FingerprintMatch{dns},
				session,
			)

			return true
		}
	}

	return false
}
