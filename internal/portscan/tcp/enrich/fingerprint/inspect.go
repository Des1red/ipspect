package fingerprint

import (
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer/recog"
	"reflect"
)

func inspect(
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

	passive := analyzer.DetectBanner(detail)

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

		analyzer.RecordMatches(
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

		analyzer.RecordMatches(
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

			analyzer.RecordMatches(
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
				analyzer.IsBinaryResponse(
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

				match := analyzeBinary(
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
					analyzer.RecordMatches(
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
			Evidence: analyzer.DescribeUnknown(
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

	enrichCapturedEvidence(
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

func enrichCapturedEvidence(
	detail *models.PortDetail,
	session *recog.Session,
) {
	target := fmt.Sprintf("port=%d", detail.Port)

	if len(detail.Fingerprint.Matches) == 0 {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.enrich-evidence [%s]: no fingerprint matches",
				target,
			),
		)

		return
	}

	matches := append(
		[]models.FingerprintMatch(nil),
		detail.Fingerprint.Matches...,
	)

	changed := false

	for i, match := range matches {
		if match.Service == "" {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.enrich-evidence [%s]: skipping match without service",
					target,
				),
			)

			continue
		}

		evidence := models.NewRecogEvidence(
			detail,
		)

		evidence.Service = match.Service

		if match.Banner != "" {
			evidence.Banner = match.Banner
		}

		if len(match.Headers) > 0 {
			evidence.Headers = match.Headers
		}

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.enrich-evidence [%s]: Recog lookup service=%q banner=%q headers=%d fields=%d raw_bytes=%d",
				target,
				evidence.Service,
				evidence.Banner,
				len(evidence.Headers),
				len(evidence.Fields),
				len(evidence.RawResponse),
			),
		)

		identity := session.RecognizePassive(
			evidence,
		)

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.enrich-evidence [%s]: passive Recog result service=%q product=%q",
				target,
				identity.Service,
				identity.Product,
			),
		)

		if identity.Service == "" &&
			len(evidence.RawResponse) > 0 {

			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.enrich-evidence [%s]: trying raw Recog recognition",
					target,
				),
			)

			identity = session.RecognizeRaw(
				evidence,
			)

			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.enrich-evidence [%s]: raw Recog result service=%q product=%q",
					target,
					identity.Service,
					identity.Product,
				),
			)
		}

		updated := mergeRecogIdentity(
			match,
			identity,
		)

		if !reflect.DeepEqual(
			match,
			updated,
		) {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.enrich-evidence [%s]: identity enriched service=%q product=%q",
					target,
					updated.Service,
					updated.Product,
				),
			)

			matches[i] = updated
			changed = true
		} else {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.enrich-evidence [%s]: no additional identity found",
					target,
				),
			)
		}
	}

	if !changed {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.enrich-evidence [%s]: fingerprint unchanged",
				target,
			),
		)

		return
	}

	analyzer.RecordMatches(
		detail,
		matches,
		session,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.enrich-evidence [%s]: fingerprint updated",
			target,
		),
	)
}
