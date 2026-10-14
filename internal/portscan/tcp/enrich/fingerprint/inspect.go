package fingerprint

import (
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer/recog"
)

func inspect(
	ip string,
	detail *models.PortDetail,
) {
	session := &recog.Session{}

	passive := analyzer.DetectBanner(detail)

	if recognizePassive(
		detail,
		passive,
		session,
	) {
		return
	}

	if passive.Service != "" &&
		passive.Service != "http" {

		analyzer.RecordMatches(
			detail,
			[]models.FingerprintMatch{passive},
			session,
		)

		return
	}

	if probeProtocols(
		ip,
		detail,
		session,
	) {
		return
	}

	if passive.Service != "" {
		analyzer.RecordMatches(
			detail,
			[]models.FingerprintMatch{passive},
			session,
		)

		return
	}

	identified, storedBinaryAnalyzed :=
		probeRawResponses(
			ip,
			detail,
			session,
		)

	if identified {
		return
	}

	// Only decode the retained response if
	// it hasn't already been analyzed.
	if !storedBinaryAnalyzed &&
		analyzer.IsBinaryResponse(
			detail.RawResponse,
		) {

		match := analyzeBinary(
			detail,
			detail.RawResponse,
			nil,
			session,
		)

		if match.Service != "" {
			analyzer.RecordMatches(
				detail,
				[]models.FingerprintMatch{match},
				session,
			)

			return
		}
	}

	detail.Fingerprint = models.FingerprintResult{
		Evidence: analyzer.DescribeUnknown(
			detail.RawResponse,
		),
	}
}

func recognizePassive(
	detail *models.PortDetail,
	passive models.FingerprintMatch,
	session *recog.Session,
) bool {
	evidence := models.NewRecogEvidence(
		detail,
	)

	match := session.RecognizePassive(
		evidence,
	)

	if match.Service == "" {
		return false
	}

	if passive.Service == match.Service &&
		passive.Confidence == "high" {

		match.Confidence = "high"
	}

	analyzer.RecordMatches(
		detail,
		[]models.FingerprintMatch{match},
		session,
	)

	return true
}
