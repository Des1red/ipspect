package fingerprint

import (
	"fmt"
	"ipspect/internal/analyzer/recog"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"reflect"
)

func EnrichCapturedEvidence(
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

		updated := MergeRecogIdentity(
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

	RecordMatches(
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
