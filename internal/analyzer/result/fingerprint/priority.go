package fingerprint

import "ipspect/internal/models"

func PreservePassiveConfidence(
	recognized models.FingerprintMatch,
	passive models.FingerprintMatch,
) models.FingerprintMatch {
	if passive.Service == recognized.Service &&
		passive.Confidence == "high" {

		recognized.Confidence = "high"
	}

	return recognized
}
