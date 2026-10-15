package fingerprint

import (
	"bytes"
	"fmt"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer/recog"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/binary"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/sender"
	"strings"
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
				analyzer.IsBinaryResponse(response),
			),
		)

		if len(detail.RawResponse) == 0 ||
			(!analyzer.IsBinaryResponse(detail.RawResponse) &&
				analyzer.IsBinaryResponse(response)) {

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
			if analyzer.IsBinaryResponse(response) {
				output.Log(
					"debug",
					fmt.Sprintf(
						"tcp.raw [%s]: binary response; invoking binary analyzer",
						target,
					),
				)

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
				output.Log(
					"debug",
					fmt.Sprintf(
						"tcp.raw [%s]: trying Nuclei matcher template=%q",
						target,
						request.ID,
					),
				)

				match = analyzer.MatchRequest(
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

		match = mergeRecogIdentity(
			match,
			identity,
		)

		analyzer.RecordMatches(
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

func analyzeBinary(
	detail *models.PortDetail,
	response []byte,
	probe *requests.Probe,
	session *recog.Session,
) models.FingerprintMatch {
	probeID := "retained-response"

	if probe != nil {
		probeID = probe.ID
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.binary [port=%d]: analyzing bytes=%d probe=%q",
			detail.Port,
			len(response),
			probeID,
		),
	)

	evidence := models.NewBinaryEvidence(
		detail,
		response,
	)

	result := binary.Analyze(
		evidence,
		probe,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.binary [port=%d]: decoder result service=%q confidence=%q product=%q evidence=%q",
			detail.Port,
			result.Match.Service,
			result.Match.Confidence,
			result.Match.Product,
			result.Match.Evidence,
		),
	)

	if result.Match.Service == "" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.binary [port=%d]: no binary signature matched",
				detail.Port,
			),
		)

		return models.FingerprintMatch{}
	}

	result.Recog.Source = models.RecogBinary
	result.Recog.Service = result.Match.Service

	if result.Recog.Banner == "" &&
		len(result.Recog.Headers) == 0 &&
		len(result.Recog.RawResponse) == 0 &&
		len(result.Recog.Fields) == 0 {

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.binary [port=%d]: no extracted Recog evidence; keeping decoder result",
				detail.Port,
			),
		)

		return result.Match
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.binary [port=%d]: querying Recog service=%q fields=%d headers=%d raw_bytes=%d",
			detail.Port,
			result.Recog.Service,
			len(result.Recog.Fields),
			len(result.Recog.Headers),
			len(result.Recog.RawResponse),
		),
	)

	identity := session.RecognizePassive(
		result.Recog,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.binary [port=%d]: passive Recog result service=%q product=%q",
			detail.Port,
			identity.Service,
			identity.Product,
		),
	)

	if identity.Service == "" &&
		len(result.Recog.RawResponse) > 0 {

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.binary [port=%d]: trying raw Recog recognition",
				detail.Port,
			),
		)

		identity = session.RecognizeRaw(
			result.Recog,
		)

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.binary [port=%d]: raw Recog result service=%q product=%q",
				detail.Port,
				identity.Service,
				identity.Product,
			),
		)
	}

	merged := mergeRecogIdentity(
		result.Match,
		identity,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.binary [port=%d]: final service=%q confidence=%q product=%q",
			detail.Port,
			merged.Service,
			merged.Confidence,
			merged.Product,
		),
	)

	return merged
}

func mergeRecogIdentity(
	match models.FingerprintMatch,
	identity models.FingerprintMatch,
) models.FingerprintMatch {
	if match.Service == "" ||
		identity.Service != match.Service {

		return match
	}

	if identity.Product != "" {
		match.Product = identity.Product
	}

	if match.Banner == "" &&
		identity.Banner != "" {

		match.Banner = identity.Banner
	}

	if len(match.Headers) == 0 &&
		len(identity.Headers) > 0 {

		match.Headers = identity.Headers
	}

	if identity.Evidence != "" &&
		!strings.Contains(
			match.Evidence,
			identity.Evidence,
		) {

		if match.Evidence != "" {
			match.Evidence += "; "
		}

		match.Evidence += identity.Evidence
	}

	return match
}
