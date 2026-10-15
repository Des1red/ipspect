package recog

import (
	"ipspect/internal/models"
	"strings"
)

func (s *Session) Enrich(
	match models.FingerprintMatch,
) models.FingerprintMatch {
	if match.Service == "" {
		return match
	}

	evidence := models.RecogEvidence{
		Service: match.Service,
		Banner:  match.Banner,
		Headers: match.Headers,
	}

	found := s.RecognizePassive(evidence)

	if found.Service == "" ||
		found.Service != match.Service {

		return match
	}

	if found.Product != "" {
		match.Product = found.Product
	}

	if found.Evidence != "" {
		if match.Evidence != "" {
			match.Evidence += "; "
		}

		match.Evidence += found.Evidence
	}

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
