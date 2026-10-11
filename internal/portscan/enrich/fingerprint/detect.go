package fingerprint

import (
	"ipspect/internal/models"
	"strings"
)

func detectBanner(
	detail *models.PortDetail,
) models.FingerprintResult {
	banner := strings.TrimSpace(
		detail.Banner,
	)

	upper := strings.ToUpper(banner)

	switch {
	case strings.HasPrefix(upper, "HTTP/"):
		service := "http"

		// The existing HTTPS enrichment
		// uses TLS for port 443.
		if detail.Port == 443 {
			service = "https"
		}

		product := ""

		for name, values := range detail.Headers {
			if strings.EqualFold(name, "Server") &&
				len(values) > 0 {

				product = values[0]
				break
			}
		}

		return models.FingerprintResult{
			Service:    service,
			Product:    product,
			Confidence: "high",
			Evidence:   "HTTP response status line",
		}

	case strings.HasPrefix(upper, "SSH-"):
		product := ""

		parts := strings.SplitN(
			banner,
			"-",
			3,
		)

		if len(parts) == 3 {
			fields := strings.Fields(parts[2])

			if len(fields) > 0 {
				product = fields[0]
			}
		}

		return models.FingerprintResult{
			Service:    "ssh",
			Product:    product,
			Confidence: "high",
			Evidence:   "SSH identification banner",
		}

	case strings.HasPrefix(upper, "220") &&
		strings.Contains(upper, "FTP"):

		return models.FingerprintResult{
			Service:    "ftp",
			Confidence: "high",
			Evidence:   "FTP server greeting",
		}

	case strings.HasPrefix(upper, "220") &&
		(strings.Contains(upper, "ESMTP") ||
			strings.Contains(upper, "SMTP")):

		return models.FingerprintResult{
			Service:    "smtp",
			Confidence: "high",
			Evidence:   "SMTP server greeting",
		}
	}

	return models.FingerprintResult{}
}
