package flow

import (
	"ipspect/internal/analyzer"
	"ipspect/internal/models"
)

func Inspect(
	ip string,
	detail *models.PortDetail,
) {
	engine := analyzer.New()

	passive, recogMatch := engine.IdentifyCaptured(
		detail,
	)

	identified := false

	switch {
	case recogMatch.Service != "":
		engine.RecordMatches(
			detail,
			[]models.FingerprintMatch{recogMatch},
		)

		identified = true

	case passive.Service != "" &&
		passive.Service != "http":

		engine.RecordMatches(
			detail,
			[]models.FingerprintMatch{passive},
		)

		identified = true

	default:
		if probeProtocols(
			ip,
			detail,
			engine,
		) {
			identified = true

		} else if passive.Service != "" {
			engine.RecordMatches(
				detail,
				[]models.FingerprintMatch{passive},
			)

			identified = true
		} else {
			found, storedBinaryAnalyzed :=
				probeRawResponses(
					ip,
					detail,
					engine,
				)

			identified = found

			if !identified &&
				!storedBinaryAnalyzed &&
				engine.IsBinaryResponse(
					detail.RawResponse,
				) {

				match := engine.AnalyzeBinary(
					detail,
					detail.RawResponse,
					nil,
				)

				if match.Service != "" {
					engine.RecordMatches(
						detail,
						[]models.FingerprintMatch{match},
					)

					identified = true
				}
			}
		}
	}

	if !identified {
		detail.Fingerprint = models.FingerprintResult{
			Evidence: engine.DescribeUnknown(
				detail.RawResponse,
			),
		}

		return
	}

	engine.EnrichCapturedEvidence(detail)
}
