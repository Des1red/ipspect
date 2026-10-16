package flow

import (
	"bytes"
	"fmt"
	"ipspect/internal/analyzer/identify"
	"ipspect/internal/analyzer/nuclei"
	"ipspect/internal/analyzer/recog"
	"ipspect/internal/analyzer/result"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/scanner/tcp/enrich/fingerprint/sender"
)

func probeRawResponses(
	ip string,
	detail *models.PortDetail,
	session *recog.Session,
) (bool, bool) {
	target := fmt.Sprintf("%s:%d", ip, detail.Port)

	search := models.NewNucleiSearch(
		ip,
		detail,
	)

	probes := requests.ForEvidence(
		search,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.raw [%s]: selected %d Nuclei probes IANA=%q",
			target,
			len(probes),
			detail.DBLookup,
		),
	)

	storedBinaryAnalyzed := false

	for _, request := range probes {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.raw [%s]: sending Nuclei template=%q expected_service=%q",
				target,
				request.ID,
				request.Service,
			),
		)

		response := sender.ProbeRaw(
			search.Target,
			search.Port,
			request,
		)

		if len(response) == 0 {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.raw [%s]: template=%q no response",
					target,
					request.ID,
				),
			)

			continue
		}

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.raw [%s]: template=%q response_bytes=%d binary=%t",
				target,
				request.ID,
				len(response),
				identify.IsBinaryResponse(response),
			),
		)

		if len(detail.RawResponse) == 0 ||
			(!identify.IsBinaryResponse(detail.RawResponse) &&
				identify.IsBinaryResponse(response)) {

			detail.RawResponse = response
			storedBinaryAnalyzed = false

			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.raw [%s]: retaining response from template=%q",
					target,
					request.ID,
				),
			)
		}

		evidence := models.RecogEvidence{
			Source:      models.RecogProbe,
			RawResponse: response,
		}

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.raw [%s]: template=%q starting raw Recog lookup",
				target,
				request.ID,
			),
		)

		match := session.RecognizeRaw(evidence)

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.raw [%s]: initial Recog result service=%q product=%q",
				target,
				match.Service,
				match.Product,
			),
		)

		if match.Service == "" {
			if identify.IsBinaryResponse(response) {
				output.Log(
					"debug",
					fmt.Sprintf(
						"tcp.raw [%s]: binary response; invoking binary analyzer",
						target,
					),
				)

				match = result.AnalyzeBinary(
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
				output.Log(
					"debug",
					fmt.Sprintf(
						"tcp.raw [%s]: trying Nuclei matcher template=%q",
						target,
						request.ID,
					),
				)

				match = nuclei.MatchRequest(
					request,
					response,
				)

				output.Log(
					"debug",
					fmt.Sprintf(
						"tcp.raw [%s]: Nuclei result template=%q service=%q confidence=%q",
						target,
						request.ID,
						match.Service,
						match.Confidence,
					),
				)
			}
		}

		if match.Service == "" {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.raw [%s]: template=%q no identification; continuing",
					target,
					request.ID,
				),
			)

			continue
		}

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.raw [%s]: service identified=%q; attempting product enrichment",
				target,
				match.Service,
			),
		)

		evidence.Service = match.Service

		identity := session.RecognizeRaw(
			evidence,
		)

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.raw [%s]: Recog enrichment service=%q product=%q evidence=%q",
				target,
				identity.Service,
				identity.Product,
				identity.Evidence,
			),
		)

		match = result.MergeRecogIdentity(
			match,
			identity,
		)

		result.RecordMatches(
			detail,
			[]models.FingerprintMatch{match},
			session,
		)

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.raw [%s]: recorded service=%q confidence=%q product=%q",
				target,
				match.Service,
				match.Confidence,
				match.Product,
			),
		)

		return true, storedBinaryAnalyzed
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.raw [%s]: exhausted Nuclei probes; no service identified",
			target,
		),
	)

	return false, storedBinaryAnalyzed
}
