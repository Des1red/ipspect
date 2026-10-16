package nuclei

import (
	"fmt"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
)

func MatchRequest(
	probe requests.Probe,
	response []byte,
) models.FingerprintMatch {
	if !requests.MatchResponse(
		probe,
		response,
	) {
		return models.FingerprintMatch{}
	}

	return models.FingerprintMatch{
		Service:    probe.Service,
		Confidence: "medium",
		Evidence: fmt.Sprintf(
			"Network detection template %q matched the response",
			probe.ID,
		),
	}
}
