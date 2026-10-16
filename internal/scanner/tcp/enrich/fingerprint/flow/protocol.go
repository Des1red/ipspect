package flow

import (
	"fmt"
	"ipspect/internal/analyzer/recog"
	"ipspect/internal/analyzer/result"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/scanner/tcp/enrich/fingerprint/sender"
)

func probeProtocols(
	ip string,
	detail *models.PortDetail,
	session *recog.Session,
) bool {
	target := fmt.Sprintf(
		"%s:%d",
		ip,
		detail.Port,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.protocol [%s]: starting probes IANA=%q",
			target,
			detail.DBLookup,
		),
	)

	// Prioritize DNS on its registered port.
	if detail.DBLookup == "domain" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.protocol [%s]: probing DNS-TCP (IANA priority)",
				target,
			),
		)

		dns := sender.ProbeDNS(
			ip,
			detail.Port,
		)

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.protocol [%s]: DNS-TCP result service=%q confidence=%q evidence=%q",
				target,
				dns.Service,
				dns.Confidence,
				dns.Evidence,
			),
		)

		if dns.Service != "" {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.protocol [%s]: DNS identified; recording match",
					target,
				),
			)

			result.RecordMatches(
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

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.protocol [%s]: probing HTTP",
			target,
		),
	)

	http := sender.ProbeHTTP(
		ip,
		detail.Port,
		false,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.protocol [%s]: HTTP result service=%q confidence=%q product=%q headers=%d",
			target,
			http.Service,
			http.Confidence,
			http.Product,
			len(http.Headers),
		),
	)

	if http.Service != "" {
		matches = append(matches, http)
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.protocol [%s]: probing HTTPS",
			target,
		),
	)

	https := sender.ProbeHTTP(
		ip,
		detail.Port,
		true,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.protocol [%s]: HTTPS result service=%q confidence=%q product=%q headers=%d",
			target,
			https.Service,
			https.Confidence,
			https.Product,
			len(https.Headers),
		),
	)

	if https.Service != "" {
		matches = append(matches, https)
	}

	if len(matches) > 0 {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.protocol [%s]: %d HTTP/HTTPS match(es); recording",
				target,
				len(matches),
			),
		)

		result.RecordMatches(
			detail,
			matches,
			session,
		)

		return true
	}

	// Check DNS on nonstandard ports.
	if detail.DBLookup != "domain" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.protocol [%s]: probing DNS-TCP (nonstandard port)",
				target,
			),
		)

		dns := sender.ProbeDNS(
			ip,
			detail.Port,
		)

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.protocol [%s]: DNS-TCP result service=%q confidence=%q evidence=%q",
				target,
				dns.Service,
				dns.Confidence,
				dns.Evidence,
			),
		)

		if dns.Service != "" {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.protocol [%s]: DNS identified; recording match",
					target,
				),
			)

			result.RecordMatches(
				detail,
				[]models.FingerprintMatch{dns},
				session,
			)

			return true
		}
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.protocol [%s]: no protocol identified",
			target,
		),
	)

	return false
}
