package recog

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"strconv"
	"strings"
)

func matchRecog(
	key string,
	service string,
	input string,
) models.FingerprintMatch {
	db := load.RecogDB(key)

	if db == nil || input == "" {
		return models.FingerprintMatch{}
	}

	if len(input) > 1024 {
		input = input[:1024]
	}

	result := db.MatchFirst(input)

	if result == nil ||
		!result.Matched ||
		len(result.Errors) > 0 {

		return models.FingerprintMatch{}
	}

	values := result.Values

	id := identity{
		vendor: strings.TrimSpace(
			values["service.vendor"],
		),
		product: strings.TrimSpace(
			values["service.product"],
		),
		version: strings.TrimSpace(
			values["service.version"],
		),
		osVendor: strings.TrimSpace(
			values["os.vendor"],
		),
		osProduct: strings.TrimSpace(
			values["os.product"],
		),
		osVersion: strings.TrimSpace(
			values["os.version"],
		),
		hwVendor: strings.TrimSpace(
			values["hw.vendor"],
		),
		hwProduct: strings.TrimSpace(
			values["hw.product"],
		),
		matched: strings.TrimSpace(
			values["matched"],
		),
		certainty: values["fp.certainty"],
	}

	if !id.identified() {
		return models.FingerprintMatch{}
	}

	return models.FingerprintMatch{
		Service: service,
		Product: id.productName(),
		Confidence: recogConfidence(
			id.certainty,
		),
		Evidence: id.evidence(key),
	}
}

func recogConfidence(
	certainty string,
) string {
	n, err := strconv.ParseFloat(
		certainty,
		64,
	)

	if err != nil {
		return "medium"
	}

	switch {
	case n >= 0.90:
		return "high"

	case n >= 0.70:
		return "medium"

	default:
		return "low"
	}
}
