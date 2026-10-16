package identify

import (
	"ipspect/internal/models"
	"net/http"
	"strings"
)

func IsHTTPSOnlyDiagnostic(
	body []byte,
) bool {
	lower := strings.ToLower(
		string(body),
	)

	return strings.Contains(
		lower,
		"http request to an https server",
	) ||
		strings.Contains(
			lower,
			"plain http request was sent to https port",
		)
}

func IdentifyHTTPResponse(
	resp *http.Response,
	secure bool,
) models.FingerprintMatch {
	service := "http"
	evidence := "HTTP response to active request"

	if secure {
		service = "https"
		evidence = "HTTP response over TLS"
	}

	headers := make(
		map[string][]string,
		len(resp.Header),
	)

	for name, values := range resp.Header {
		if strings.EqualFold(
			name,
			"Set-Cookie",
		) ||
			strings.EqualFold(
				name,
				"WWW-Authenticate",
			) ||
			strings.EqualFold(
				name,
				"Proxy-Authenticate",
			) {

			headers[name] = []string{
				"[redacted]",
			}

			continue
		}

		headers[name] = append(
			[]string(nil),
			values...,
		)
	}

	return models.FingerprintMatch{
		Service:    service,
		Confidence: "high",

		Product: resp.Header.Get(
			"Server",
		),

		Evidence: evidence,

		Banner: resp.Proto +
			" " +
			resp.Status,

		Headers: headers,
	}
}
