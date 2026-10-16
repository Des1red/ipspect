package result

import (
	"fmt"
	"ipspect/internal/analyzer/binary"
	"ipspect/internal/analyzer/recog"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"ipspect/internal/output"
)

func AnalyzeBinary(
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

	merged := MergeRecogIdentity(
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
