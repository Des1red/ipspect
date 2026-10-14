package binary

import (
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer"
)

func extractInfo(
	evidence models.BinaryEvidence,
	probe *requests.Probe,
) models.BinaryResult {
	if probe == nil ||
		len(evidence.RawResponse) == 0 {

		return models.BinaryResult{}
	}

	match := analyzer.MatchRequest(
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
