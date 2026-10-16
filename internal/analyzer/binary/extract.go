package binary

import (
	"ipspect/internal/analyzer/nuclei"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
)

func extractInfo(
	evidence models.BinaryEvidence,
	probe *requests.Probe,
) models.BinaryResult {
	if probe == nil ||
		len(evidence.RawResponse) == 0 {

		return models.BinaryResult{}
	}

	match := nuclei.MatchRequest(
		*probe,
		evidence.RawResponse,
	)

	if match.Service == "" {
		return models.BinaryResult{}
	}

	return models.BinaryResult{
		Match: match,
	}
}
