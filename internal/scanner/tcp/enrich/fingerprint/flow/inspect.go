package flow

import (
	"fmt"
	"ipspect/internal/analyzer/identify"
	"ipspect/internal/analyzer/recog"
	"ipspect/internal/analyzer/result"
	"ipspect/internal/models"
	"ipspect/internal/output"
)

func Inspect(
	ip string,
	detail *models.PortDetail,
) {
	target := fmt.Sprintf("%s:%d", ip, detail.Port)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.inspect [%s]: starting IANA=%q banner=%q raw_bytes=%d",
			target,
			detail.DBLookup,
			detail.Banner,
			len(detail.RawResponse),
		),
	)

	session := &recog.Session{}

	passive := identify.DetectBanner(detail)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.inspect [%s]: passive detector service=%q confidence=%q product=%q",
			target,
			passive.Service,
			passive.Confidence,
			passive.Product,
		),
	)

	evidence := models.NewRecogEvidence(detail)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.inspect [%s]: querying Recog using captured evidence",
			target,
		),
	)

	recogMatch := session.RecognizePassive(
		evidence,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.inspect [%s]: Recog result service=%q confidence=%q product=%q evidence=%q",
			target,
			recogMatch.Service,
			recogMatch.Confidence,
			recogMatch.Product,
			recogMatch.Evidence,
		),
	)

	identified := false

	switch {
	case recogMatch.Service != "":
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.inspect [%s]: selecting Recog identification",
				target,
			),
		)

		if passive.Service == recogMatch.Service &&
			passive.Confidence == "high" {

			recogMatch.Confidence = "high"

			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.inspect [%s]: preserving high passive confidence",
					target,
				),
			)
		}

		result.RecordMatches(
			detail,
			[]models.FingerprintMatch{recogMatch},
			session,
		)

		identified = true

	case passive.Service != "" &&
		passive.Service != "http":

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.inspect [%s]: selecting passive identification service=%q",
				target,
				passive.Service,
			),
		)

		result.RecordMatches(
			detail,
			[]models.FingerprintMatch{passive},
			session,
		)

		identified = true

	default:
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.inspect [%s]: proceeding to active protocol probes",
				target,
			),
		)

		if probeProtocols(
			ip,
			detail,
			session,
		) {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.inspect [%s]: active protocol probe identified service",
					target,
				),
			)

			identified = true

		} else if passive.Service != "" {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.inspect [%s]: using passive fallback service=%q",
					target,
					passive.Service,
				),
			)

			result.RecordMatches(
				detail,
				[]models.FingerprintMatch{passive},
				session,
			)

			identified = true
		} else {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.inspect [%s]: starting Nuclei raw probes",
					target,
				),
			)

			found, storedBinaryAnalyzed :=
				probeRawResponses(
					ip,
					detail,
					session,
				)

			identified = found

			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.inspect [%s]: raw probe result identified=%t retained_binary_analyzed=%t",
					target,
					identified,
					storedBinaryAnalyzed,
				),
			)

			if !identified &&
				!storedBinaryAnalyzed &&
				identify.IsBinaryResponse(
					detail.RawResponse,
				) {

				output.Log(
					"debug",
					fmt.Sprintf(
						"tcp.inspect [%s]: analyzing retained binary response bytes=%d",
						target,
						len(detail.RawResponse),
					),
				)

				match := result.AnalyzeBinary(
					detail,
					detail.RawResponse,
					nil,
					session,
				)

				output.Log(
					"debug",
					fmt.Sprintf(
						"tcp.inspect [%s]: retained binary result service=%q product=%q evidence=%q",
						target,
						match.Service,
						match.Product,
						match.Evidence,
					),
				)

				if match.Service != "" {
					result.RecordMatches(
						detail,
						[]models.FingerprintMatch{match},
						session,
					)

					identified = true
				}
			}
		}
	}

	if !identified {
		detail.Fingerprint = models.FingerprintResult{
			Evidence: identify.DescribeUnknown(
				detail.RawResponse,
			),
		}

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.inspect [%s]: unidentified evidence=%q",
				target,
				detail.Fingerprint.Evidence,
			),
		)

		return
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.inspect [%s]: starting captured evidence enrichment",
			target,
		),
	)

	result.EnrichCapturedEvidence(
		detail,
		session,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.inspect [%s]: completed service=%q confidence=%q product=%q matches=%d",
			target,
			detail.Fingerprint.Service,
			detail.Fingerprint.Confidence,
			detail.Fingerprint.Product,
			len(detail.Fingerprint.Matches),
		),
	)

	for _, match := range detail.Fingerprint.Matches {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.inspect [%s]: final match service=%q confidence=%q product=%q evidence=%q",
				target,
				match.Service,
				match.Confidence,
				match.Product,
				match.Evidence,
			),
		)
	}
}
