package recog

import (
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"sort"
	"strings"
)

func (s *Session) matchGreeting(
	evidence models.RecogEvidence,
) (models.FingerprintMatch, bool) {
	banner := strings.TrimSpace(evidence.Banner)
	upper := strings.ToUpper(banner)

	if strings.HasPrefix(upper, "SSH-") {
		parts := strings.SplitN(banner, "-", 3)

		if len(parts) == 3 &&
			(parts[1] == "2.0" ||
				parts[1] == "1.99" ||
				parts[1] == "1.5") {

			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.recog.normalize: SSH greeting normalized db=%q input=%q",
					"ssh.banner",
					parts[2],
				),
			)

			match := s.matchField(
				"ssh.banner",
				parts[2],
				evidence.Service,
			)

			if match.Service != "" {
				match.Confidence = "high"
				match.Banner = banner

				output.Log(
					"debug",
					fmt.Sprintf(
						"tcp.recog.normalize: SSH identified product=%q",
						match.Product,
					),
				)
			} else {
				output.Log(
					"debug",
					"tcp.recog.normalize: SSH signature not recognized",
				)
			}

			return match, false
		}

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.normalize: unsupported SSH greeting format=%q",
				banner,
			),
		)
	}

	if !strings.HasPrefix(banner, "220 ") &&
		!strings.HasPrefix(banner, "220-") {

		return models.FingerprintMatch{}, false
	}

	// FTP and SMTP share greeting code 220.
	// Preserve ambiguity handling.
	service := protocolFamily(evidence.Service)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.normalize: 220 greeting detected confirmed_service=%q",
			service,
		),
	)

	if service != "" &&
		service != "ftp" &&
		service != "smtp" {

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.normalize: rejecting 220 greeting for incompatible service=%q",
				service,
			),
		)

		return models.FingerprintMatch{}, true
	}

	value := strings.TrimSpace(banner[4:])

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.normalize: 220 greeting normalized input=%q checking ftp.banner and smtp.banner",
			value,
		),
	)

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

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.normalize: greeting candidates ftp=%q smtp=%q",
			ftp.Product,
			smtp.Product,
		),
	)

	if ftp.Service != "" &&
		(service == "" || service == "ftp") &&
		(smtp.Service == "" || service == "ftp") {

		if strings.Contains(upper, "FTP") &&
			!strings.Contains(upper, "SMTP") {

			ftp.Confidence = "high"
		}

		ftp.Banner = banner

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.normalize: selected FTP product=%q confidence=%q",
				ftp.Product,
				ftp.Confidence,
			),
		)

		return ftp, true
	}

	if smtp.Service != "" &&
		(service == "" || service == "smtp") &&
		(ftp.Service == "" || service == "smtp") {

		if strings.Contains(upper, "SMTP") {
			smtp.Confidence = "high"
		}

		smtp.Banner = banner

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.normalize: selected SMTP product=%q confidence=%q",
				smtp.Product,
				smtp.Confidence,
			),
		)

		return smtp, true
	}

	output.Log(
		"debug",
		"tcp.recog.normalize: ambiguous or unmatched 220 greeting",
	)

	return models.FingerprintMatch{}, true
}

func (s *Session) matchHTTPHeaders(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	banner := strings.TrimSpace(evidence.Banner)

	if !strings.HasPrefix(
		strings.ToUpper(banner),
		"HTTP/",
	) && protocolFamily(evidence.Service) != "http" {

		return models.FingerprintMatch{}
	}

	names := make(
		[]string,
		0,
		len(evidence.Headers),
	)

	for name := range evidence.Headers {
		names = append(names, name)
	}

	sort.Strings(names)

	// Keep Server first to preserve existing
	// product-selection priority.
	sort.SliceStable(
		names,
		func(i, j int) bool {
			return strings.EqualFold(
				names[i],
				"Server",
			) && !strings.EqualFold(
				names[j],
				"Server",
			)
		},
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.normalize: HTTP detected service=%q headers=%d",
			evidence.Service,
			len(names),
		),
	)

	for _, name := range names {
		// Authentication and cookie values are
		// not part of this expansion.
		if strings.EqualFold(name, "Set-Cookie") ||
			strings.EqualFold(name, "WWW-Authenticate") ||
			strings.EqualFold(name, "Proxy-Authenticate") {

			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.recog.normalize: HTTP header skipped name=%q",
					name,
				),
			)

			continue
		}

		key := "http_header." +
			strings.ToLower(
				strings.ReplaceAll(name, "-", ""),
			)

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.normalize: HTTP header=%q mapped_to=%q values=%d",
				name,
				key,
				len(evidence.Headers[name]),
			),
		)

		for _, value := range evidence.Headers[name] {
			value = strings.TrimSpace(value)

			match := s.matchField(
				key,
				value,
				evidence.Service,
			)

			if match.Service == "" {
				continue
			}

			match.Confidence = "high"
			match.Banner = banner
			match.Headers = evidence.Headers

			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.recog.normalize: HTTP matched db=%q product=%q",
					key,
					match.Product,
				),
			)

			return match
		}
	}

	output.Log(
		"debug",
		"tcp.recog.normalize: no HTTP header signature matched",
	)

	return models.FingerprintMatch{}
}
