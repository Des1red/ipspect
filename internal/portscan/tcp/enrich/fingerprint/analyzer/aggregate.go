package analyzer

import (
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer/recog"
	"strings"
)

func RecordMatches(
	detail *models.PortDetail,
	matches []models.FingerprintMatch,
) {
	analyzed := make(
		[]models.FingerprintMatch,
		0,
		len(matches),
	)

	for _, match := range matches {
		if !strings.Contains(
			match.Evidence,
			"Rapid7 Recog [",
		) {
			match = recog.Enrich(match)
		}

		analyzed = append(
			analyzed,
			match,
		)
	}

	fp := models.FingerprintResult{
		Matches:    analyzed,
		Confidence: matchesConfidence(analyzed),
	}

	names := make(
		[]string,
		0,
		len(analyzed),
	)

	products := make(
		[]string,
		0,
		len(analyzed),
	)

	evidences := make(
		[]string,
		0,
		len(analyzed),
	)

	for _, match := range analyzed {
		names = append(
			names,
			match.Service,
		)

		evidences = append(
			evidences,
			match.Evidence,
		)

		if match.Product != "" {
			products = append(
				products,
				match.Product,
			)
		}

		if detail.Banner == "" &&
			match.Banner != "" {

			detail.Banner = match.Banner
		}

		if len(detail.Headers) == 0 &&
			len(match.Headers) > 0 {

			detail.Headers = match.Headers
		}
	}

	fp.Service = strings.Join(names, "+")
	fp.Product = strings.Join(products, " | ")
	fp.Evidence = strings.Join(evidences, "; ")

	detail.Fingerprint = fp
}
