package fingerprint

import (
	"ipspect/internal/analyzer/identify"
	"ipspect/internal/analyzer/nuclei"
	"ipspect/internal/analyzer/recog"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
)

func AnalyzeRawResponse(
	detail *models.PortDetail,
	response []byte,
	probe *requests.Probe,
	session *recog.Session,
) (models.FingerprintMatch, bool) {
	evidence := models.RecogEvidence{
		Source:      models.RecogProbe,
		RawResponse: response,
	}

	match := session.RecognizeRaw(evidence)
	binaryAnalyzed := false

	if match.Service == "" {
		if identify.IsBinaryResponse(response) {
			match = AnalyzeBinary(
				detail,
				response,
				probe,
				session,
			)

			binaryAnalyzed = true
		} else {
			match = nuclei.MatchRequest(
				*probe,
				response,
			)
		}
	}

	if match.Service == "" {
		return match, binaryAnalyzed
	}

	evidence.Service = match.Service

	identity := session.RecognizeRaw(
		evidence,
	)

	match = MergeRecogIdentity(
		match,
		identity,
	)

	return match, binaryAnalyzed
}
