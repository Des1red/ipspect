package recog

import (
	"fmt"
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"strconv"
	"strings"
)

func matchRecog(
	key string,
	service string,
	input string,
) models.FingerprintMatch {
	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.match: lookup db=%q service=%q input=%q",
			key,
			service,
			input,
		),
	)

	db := load.RecogDB(key)

	if db == nil {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.match: database not found key=%q",
				key,
			),
		)

		return models.FingerprintMatch{}
	}

	if input == "" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.match: empty input db=%q",
				key,
			),
		)

		return models.FingerprintMatch{}
	}

	if len(input) > 1024 {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.match: truncating input db=%q bytes=%d limit=1024",
				key,
				len(input),
			),
		)

		input = input[:1024]
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.match: searching db=%q signatures=%d",
			key,
			len(db.Fingerprints),
		),
	)

	result := db.MatchFirst(input)

	if result == nil {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.match: no result db=%q",
				key,
			),
		)

		return models.FingerprintMatch{}
	}

	if !result.Matched || len(result.Errors) > 0 {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.match: no usable match db=%q matched=%t errors=%d",
				key,
				result.Matched,
				len(result.Errors),
			),
		)

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

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.match: signature matched db=%q vendor=%q product=%q version=%q os=%q hardware=%q certainty=%q",
			key,
			id.vendor,
			id.product,
			id.version,
			strings.TrimSpace(
				id.osVendor+" "+id.osProduct+" "+id.osVersion,
			),
			strings.TrimSpace(
				id.hwVendor+" "+id.hwProduct,
			),
			id.certainty,
		),
	)

	if !id.identified() {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.match: signature has no usable identity db=%q",
				key,
			),
		)

		return models.FingerprintMatch{}
	}

	match := models.FingerprintMatch{
		Service: service,
		Product: id.productName(),
		Confidence: recogConfidence(
			id.certainty,
		),
		Evidence: id.evidence(key),
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.match: IDENTIFIED db=%q service=%q product=%q confidence=%q evidence=%q",
			key,
			match.Service,
			match.Product,
			match.Confidence,
			match.Evidence,
		),
	)

	return match
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
