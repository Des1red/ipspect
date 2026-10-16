package recog

import (
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"strings"
)

func (s *Session) Enrich(
	match models.FingerprintMatch,
) models.FingerprintMatch {
	if match.Service == "" {
		output.Log(
			"debug",
			"tcp.recog.enrich: skipped reason=no-service",
		)

		return match
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.enrich: starting service=%q product=%q banner=%q headers=%d",
			match.Service,
			match.Product,
			match.Banner,
			len(match.Headers),
		),
	)

	evidence := models.RecogEvidence{
		Service: match.Service,
		Banner:  match.Banner,
		Headers: match.Headers,
	}

	found := s.RecognizePassive(evidence)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.enrich: result service=%q product=%q evidence=%q",
			found.Service,
			found.Product,
			found.Evidence,
		),
	)

	if found.Service == "" ||
		found.Service != match.Service {

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.enrich: unchanged original_service=%q recog_service=%q",
				match.Service,
				found.Service,
			),
		)

		return match
	}

	if found.Product != "" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.enrich: product %q -> %q",
				match.Product,
				found.Product,
			),
		)

		match.Product = found.Product
	}

	if found.Evidence != "" {
		if match.Evidence != "" {
			match.Evidence += "; "
		}

		match.Evidence += found.Evidence
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.enrich: completed service=%q product=%q",
			match.Service,
			match.Product,
		),
	)

	return match
}

func serverHeader(
	headers map[string][]string,
) string {
	for key, values := range headers {
		if strings.EqualFold(key, "Server") &&
			len(values) > 0 {

			return strings.TrimSpace(values[0])
		}
	}

	return ""
}
