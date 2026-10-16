package identify

import (
	"ipspect/internal/models"
	"strings"
)

func DetectBanner(
	detail *models.PortDetail,
) models.FingerprintMatch {
	banner := strings.TrimSpace(
		detail.Banner,
	)

	upper := strings.ToUpper(banner)

	switch {
	case strings.HasPrefix(upper, "HTTP/"):
		product := ""

		for name, values := range detail.Headers {
			if strings.EqualFold(name, "Server") &&
				len(values) > 0 {

				product = values[0]
				break
			}
		}

		return models.FingerprintMatch{
			Service:    "http",
			Confidence: "high",
			Product:    product,
			Evidence:   "Plaintext HTTP status line",
			Banner:     banner,
			Headers:    detail.Headers,
		}

	case strings.HasPrefix(upper, "SSH-"):
		product := ""

		parts := strings.SplitN(
			banner,
			"-",
			3,
		)

		if len(parts) == 3 {
			fields := strings.Fields(
				parts[2],
			)

			if len(fields) > 0 {
				product = fields[0]
			}
		}

		return models.FingerprintMatch{
			Service:    "ssh",
			Confidence: "high",
			Product:    product,
			Evidence:   "SSH identification banner",
			Banner:     banner,
		}

	case strings.HasPrefix(upper, "220") &&
		strings.Contains(upper, "FTP"):

		return models.FingerprintMatch{
			Service:    "ftp",
			Confidence: "high",
			Evidence:   "FTP server greeting",
			Banner:     banner,
		}

	case strings.HasPrefix(upper, "220") &&
		(strings.Contains(upper, "ESMTP") ||
			strings.Contains(upper, "SMTP")):

		return models.FingerprintMatch{
			Service:    "smtp",
			Confidence: "high",
			Evidence:   "SMTP server greeting",
			Banner:     banner,
		}
	}

	return models.FingerprintMatch{}
}
