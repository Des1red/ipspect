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
	passive := analyzer.DetectBanner(detail)

	if recognizePassive(detail, passive) {
		return
	}

	if passive.Service != "" &&
		passive.Service != "http" {

		analyzer.RecordMatches(
			detail,
			[]models.FingerprintMatch{passive},
		)

		return
	}

	if probeProtocols(ip, detail) {
		return
	}

	if passive.Service != "" {
		analyzer.RecordMatches(
			detail,
			[]models.FingerprintMatch{passive},
		)

		return
	}

	if probeRawResponses(ip, detail) {
		return
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
) bool {
	evidence := models.NewRecogEvidence(
		detail,
	)

	match := recog.RecognizePassive(
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
	)

	return true
}
