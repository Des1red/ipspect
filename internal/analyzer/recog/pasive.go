package recog

import (
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
)

func (s *Session) RecognizePassive(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.passive: start source=%q service=%q hint=%q banner=%q headers=%d fields=%d",
			evidence.Source,
			evidence.Service,
			evidence.ServiceHint,
			evidence.Banner,
			len(evidence.Headers),
			len(evidence.Fields),
		),
	)

	// Protocol-specific greeting normalization.
	match, handled := s.matchGreeting(evidence)

	if handled {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.passive: greeting handled matched=%t service=%q product=%q",
				match.Service != "",
				match.Service,
				match.Product,
			),
		)

		return match
	}

	if match.Service != "" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.passive: greeting identified service=%q product=%q",
				match.Service,
				match.Product,
			),
		)

		return match
	}

	// HTTP header signatures from the registry.
	output.Log(
		"debug",
		"tcp.recog.passive: checking HTTP header signatures",
	)

	match = s.matchHTTPHeaders(evidence)

	if match.Service != "" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.passive: HTTP identified service=%q product=%q",
				match.Service,
				match.Product,
			),
		)

		return match
	}

	// Explicit fields supplied by other decoders.
	output.Log(
		"debug",
		"tcp.recog.passive: checking typed evidence",
	)

	match = s.matchTypedFields(evidence)

	if match.Service != "" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.passive: typed evidence identified service=%q product=%q",
				match.Service,
				match.Product,
			),
		)

		return match
	}

	// Additional full-banner databases.
	output.Log(
		"debug",
		"tcp.recog.passive: checking compatible banner databases",
	)

	match = s.matchProtocolBanner(evidence)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.passive: completed matched=%t service=%q product=%q",
			match.Service != "",
			match.Service,
			match.Product,
		),
	)

	return match
}
