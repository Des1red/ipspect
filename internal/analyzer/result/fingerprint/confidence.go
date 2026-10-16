package fingerprint

import "ipspect/internal/models"

func confidenceRank(
	value string,
) int {
	switch value {
	case "high":
		return 3

	case "medium":
		return 2

	case "low":
		return 1

	default:
		return 0
	}
}

func matchesConfidence(
	matches []models.FingerprintMatch,
) string {
	if len(matches) == 0 {
		return ""
	}

	result := "high"

	for _, match := range matches {
		confidence := match.Confidence

		if confidenceRank(confidence) == 0 {
			confidence = "low"
		}

		if confidenceRank(confidence) <
			confidenceRank(result) {

			result = confidence
		}
	}

	return result
}
