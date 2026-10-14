package recog

import (
	"ipspect/internal/models"
	"strings"
)

func RecognizePassive(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	banner := strings.TrimSpace(
		evidence.Banner,
	)

	upper := strings.ToUpper(banner)

	if strings.HasPrefix(upper, "SSH-") {
		parts := strings.SplitN(
			banner,
			"-",
			3,
		)

		if len(parts) == 3 &&
			(parts[1] == "2.0" ||
				parts[1] == "1.99" ||
				parts[1] == "1.5") {

			match := matchRecog(
				"ssh.banner",
				"ssh",
				parts[2],
			)

			if match.Service != "" {
				match.Confidence = "high"
				match.Banner = banner
			}

			return match
		}
	}

	if strings.HasPrefix(banner, "220 ") ||
		strings.HasPrefix(banner, "220-") {

		value := strings.TrimSpace(
			banner[4:],
		)

		ftp := matchRecog(
			"ftp.banner",
			"ftp",
			value,
		)

		smtp := matchRecog(
			"smtp.banner",
			"smtp",
			value,
		)

		// FTP and SMTP share greeting code 220.
		// Do not guess when both databases match.
		if ftp.Service != "" &&
			smtp.Service == "" {

			if strings.Contains(upper, "FTP") &&
				!strings.Contains(upper, "SMTP") {

				ftp.Confidence = "high"
			}

			ftp.Banner = banner

			return ftp
		}

		if smtp.Service != "" &&
			ftp.Service == "" {

			if strings.Contains(upper, "SMTP") {
				smtp.Confidence = "high"
			}

			smtp.Banner = banner

			return smtp
		}

		return models.FingerprintMatch{}
	}

	if strings.HasPrefix(upper, "HTTP/") {
		if value := serverHeader(
			evidence.Headers,
		); value != "" {

			match := matchRecog(
				"http_header.server",
				"http",
				value,
			)

			if match.Service != "" {
				match.Confidence = "high"
				match.Banner = banner
				match.Headers = evidence.Headers
			}

			return match
		}
	}

	return models.FingerprintMatch{}
}
