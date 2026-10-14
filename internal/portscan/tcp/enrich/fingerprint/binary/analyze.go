package binary

import (
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
)

func Analyze(
	evidence models.BinaryEvidence,
	probe *requests.Probe,
) models.BinaryResult {
	if len(evidence.RawResponse) == 0 {
		return models.BinaryResult{}
	}

	// First attempt Nuclei signature matching.
	result := extractInfo(
		evidence,
		probe,
	)

	if result.Match.Service != "" {
		return result
	}

	// Fallback to binary protocol decoding.
	return decode(evidence)
}
