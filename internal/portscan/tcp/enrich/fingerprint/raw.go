package fingerprint

import (
	"bytes"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer/recog"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/binary"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/sender"
)

func probeRawResponses(
	ip string,
	detail *models.PortDetail,
	session *recog.Session,
) (bool, bool) {
	search := models.NewNucleiSearch(
		ip,
		detail,
	)

	probes := requests.ForEvidence(
		search,
	)

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
			(!analyzer.IsBinaryResponse(detail.RawResponse) &&
				analyzer.IsBinaryResponse(response)) {

			detail.RawResponse = response
			storedBinaryAnalyzed = false
		}

		match := session.RecognizeRaw(
			models.RecogEvidence{
				RawResponse: response,
			},
		)

		if match.Service == "" {
			if analyzer.IsBinaryResponse(response) {
				match = analyzeBinary(
					detail,
					response,
					&request,
					session,
				)

				if bytes.Equal(
					detail.RawResponse,
					response,
				) {
					storedBinaryAnalyzed = true
				}
			} else {
				match = analyzer.MatchRequest(
					request,
					response,
				)
			}
		}

		if match.Service == "" {
			continue
		}

		analyzer.RecordMatches(
			detail,
			[]models.FingerprintMatch{match},
			session,
		)

		return true, storedBinaryAnalyzed
	}

	return false, storedBinaryAnalyzed
}

func analyzeBinary(
	detail *models.PortDetail,
	response []byte,
	probe *requests.Probe,
	session *recog.Session,
) models.FingerprintMatch {
	evidence := models.NewBinaryEvidence(
		detail,
		response,
	)

	result := binary.Analyze(
		evidence,
		probe,
	)

	if result.Match.Service == "" {
		return models.FingerprintMatch{}
	}

	if result.Recog.Banner == "" &&
		len(result.Recog.Headers) == 0 &&
		len(result.Recog.RawResponse) == 0 {

		return result.Match
	}

	recogMatch := session.RecognizePassive(
		result.Recog,
	)

	if recogMatch.Service == "" &&
		len(result.Recog.RawResponse) > 0 {

		recogMatch = session.RecognizeRaw(
			result.Recog,
		)
	}

	if recogMatch.Service != result.Match.Service {
		return result.Match
	}

	if recogMatch.Product != "" {
		result.Match.Product = recogMatch.Product
	}

	if result.Match.Banner == "" &&
		recogMatch.Banner != "" {

		result.Match.Banner = recogMatch.Banner
	}

	if len(result.Match.Headers) == 0 &&
		len(recogMatch.Headers) > 0 {

		result.Match.Headers = recogMatch.Headers
	}

	if recogMatch.Evidence != "" {
		if result.Match.Evidence != "" {
			result.Match.Evidence += "; "
		}

		result.Match.Evidence += recogMatch.Evidence
	}

	return result.Match
}
