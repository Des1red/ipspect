package fingerprint

import (
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer/recog"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/sender"
)

func probeRawResponses(
	ip string,
	detail *models.PortDetail,
) bool {
	probes := requests.ForPort(
		detail.Port,
	)

	for _, request := range probes {
		response := sender.ProbeRaw(
			ip,
			detail.Port,
			request,
		)

		if len(response) == 0 {
			continue
		}

		if len(detail.RawResponse) == 0 ||
			(!analyzer.IsBinaryResponse(detail.RawResponse) &&
				analyzer.IsBinaryResponse(response)) {

			detail.RawResponse = response
		}

		match := recog.RecognizeRaw(
			response,
		)

		if match.Service == "" {
			match = analyzer.MatchRequest(
				request,
				response,
			)
		}

		if match.Service == "" {
			continue
		}

		analyzer.RecordMatches(
			detail,
			[]models.FingerprintMatch{match},
		)

		return true
	}

	return false
}
