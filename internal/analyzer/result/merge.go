package result

import (
	"ipspect/internal/models"
	"strings"
)

func MergeRecogIdentity(
	match models.FingerprintMatch,
	identity models.FingerprintMatch,
) models.FingerprintMatch {
	if match.Service == "" ||
		identity.Service != match.Service {

		return match
	}

	if identity.Product != "" {
		match.Product = identity.Product
	}

	if match.Banner == "" &&
		identity.Banner != "" {

		match.Banner = identity.Banner
	}

	if len(match.Headers) == 0 &&
		len(identity.Headers) > 0 {

		match.Headers = identity.Headers
	}

	if identity.Evidence != "" &&
		!strings.Contains(
			match.Evidence,
			identity.Evidence,
		) {

		if match.Evidence != "" {
			match.Evidence += "; "
		}

		match.Evidence += identity.Evidence
	}

	return match
}
