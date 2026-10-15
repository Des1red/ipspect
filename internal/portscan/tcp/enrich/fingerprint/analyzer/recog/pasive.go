package recog

import (
	"ipspect/internal/models"
	"strings"
)

func (s *Session) RecognizePassive(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	banner := strings.TrimSpace(evidence.Banner)
	upper := strings.ToUpper(banner)

	// SSH software identification.
	if strings.HasPrefix(upper, "SSH-") {
		parts := strings.SplitN(banner, "-", 3)

		if len(parts) == 3 &&
			(parts[1] == "2.0" ||
				parts[1] == "1.99" ||
				parts[1] == "1.5") {

			match := s.matchField(
				"ssh.banner",
				parts[2],
				evidence.Service,
			)

			if match.Service != "" {
				match.Confidence = "high"
				match.Banner = banner

				return match
			}
		}
	}

	// FTP and SMTP share the 220 greeting.
	if strings.HasPrefix(banner, "220 ") ||
		strings.HasPrefix(banner, "220-") {

		value := strings.TrimSpace(banner[4:])

		ftp := s.matchField(
			"ftp.banner",
			value,
			"",
		)

		smtp := s.matchField(
			"smtp.banner",
			value,
			"",
		)

		if evidence.Service != "" &&
			protocolFamily(evidence.Service) != "ftp" &&
			protocolFamily(evidence.Service) != "smtp" {

			return models.FingerprintMatch{}
		}

		if ftp.Service != "" &&
			(evidence.Service == "" ||
				protocolFamily(evidence.Service) == "ftp") &&
			(smtp.Service == "" ||
				protocolFamily(evidence.Service) == "ftp") {

			if strings.Contains(upper, "FTP") &&
				!strings.Contains(upper, "SMTP") {

				ftp.Confidence = "high"
			}

			ftp.Banner = banner

			return ftp
		}

		if smtp.Service != "" &&
			(evidence.Service == "" ||
				protocolFamily(evidence.Service) == "smtp") &&
			(ftp.Service == "" ||
				protocolFamily(evidence.Service) == "smtp") {

			if strings.Contains(upper, "SMTP") {
				smtp.Confidence = "high"
			}

			smtp.Banner = banner

			return smtp
		}

		// An ambiguous 220 greeting remains unknown.
		return models.FingerprintMatch{}
	}

	// HTTP Server header.
	if strings.HasPrefix(upper, "HTTP/") ||
		protocolFamily(evidence.Service) == "http" {

		value := serverHeader(evidence.Headers)

		if value != "" {
			match := s.matchField(
				"http_header.server",
				value,
				evidence.Service,
			)

			if match.Service != "" {
				match.Confidence = "high"
				match.Banner = banner
				match.Headers = evidence.Headers

				return match
			}
		}
	}

	// Fields supplied by protocol-specific
	// extractors and future decoders.
	if match := s.matchTypedFields(
		evidence,
	); match.Service != "" {

		return match
	}

	// Generic routing based on the loaded
	// database's protocol metadata.
	return s.matchProtocolBanner(evidence)
}
