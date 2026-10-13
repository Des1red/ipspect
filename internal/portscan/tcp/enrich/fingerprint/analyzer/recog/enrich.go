package recog

import (
	"ipspect/internal/models"
	"strings"
)

func Enrich(
	match models.FingerprintMatch,
) models.FingerprintMatch {
	var key, value string

	switch match.Service {
	case "ssh":
		parts := strings.SplitN(
			strings.TrimSpace(match.Banner),
			"-",
			3,
		)

		if len(parts) == 3 &&
			parts[0] == "SSH" {

			key = "ssh.banner"
			value = parts[2]
		}

	case "ftp", "smtp":
		banner := strings.TrimSpace(match.Banner)

		if strings.HasPrefix(banner, "220 ") ||
			strings.HasPrefix(banner, "220-") {

			key = match.Service + ".banner"
			value = strings.TrimSpace(banner[4:])
		}

	case "http", "https":
		key = "http_header.server"
		value = serverHeader(match.Headers)
	}

	if key == "" || value == "" {
		return match
	}

	found := matchRecog(
		key,
		match.Service,
		value,
	)

	if found.Service == "" {
		return match
	}

	if found.Product != "" {
		match.Product = found.Product
	}

	if match.Evidence != "" {
		match.Evidence += "; "
	}

	match.Evidence += found.Evidence

	return match
}

func serverHeader(
	headers map[string][]string,
) string {
	for key, values := range headers {
		if strings.EqualFold(key, "Server") &&
			len(values) > 0 {

			return strings.TrimSpace(values[0])
		}
	}

	return ""
}
