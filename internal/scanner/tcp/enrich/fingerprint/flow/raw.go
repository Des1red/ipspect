package flow

import (
	"bytes"
	"ipspect/internal/analyzer"
	"ipspect/internal/models"
	"ipspect/internal/scanner/tcp/enrich/fingerprint/sender"
)

func probeRawResponses(
	ip string,
	detail *models.PortDetail,
	engine *analyzer.Engine,
) (bool, bool) {
	search := models.NewNucleiSearch(
		ip,
		detail,
	)

	probes := engine.SelectProbes(search)

	storedBinaryAnalyzed := false

	for _, request := range probes {
		response := sender.ProbeRaw(
			search.Target,
			search.Port,
			request,
		)

		if len(response) == 0 {
			continue
		}

		if len(detail.RawResponse) == 0 ||
			(!engine.IsBinaryResponse(detail.RawResponse) &&
				engine.IsBinaryResponse(response)) {

			detail.RawResponse = response
			storedBinaryAnalyzed = false
		}

		match, binaryAnalyzed :=
			engine.AnalyzeRawResponse(
				detail,
				response,
				&request,
			)

		if binaryAnalyzed &&
			bytes.Equal(
				detail.RawResponse,
				response,
			) {

			storedBinaryAnalyzed = true
		}

		if match.Service == "" {
			continue
		}

		engine.RecordMatches(
			detail,
			[]models.FingerprintMatch{match},
		)

		return true, storedBinaryAnalyzed
	}

	return false, storedBinaryAnalyzed
}
