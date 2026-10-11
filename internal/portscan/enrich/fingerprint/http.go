package fingerprint

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"ipspect/internal/models"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const probeTimeout = 750 * time.Millisecond

func probeHTTP(
	ip string,
	port int,
	secure bool,
) models.FingerprintMatch {
	address := net.JoinHostPort(
		ip,
		strconv.Itoa(port),
	)

	dialer := &net.Dialer{
		Timeout: probeTimeout,
	}

	var conn net.Conn
	var err error

	if secure {
		conn, err = tls.DialWithDialer(
			dialer,
			"tcp",
			address,
			&tls.Config{
				InsecureSkipVerify: true,
			},
		)
	} else {
		conn, err = dialer.Dial(
			"tcp",
			address,
		)
	}

	if err != nil {
		return models.FingerprintMatch{}
	}

	defer conn.Close()

	if err := conn.SetDeadline(
		time.Now().Add(probeTimeout),
	); err != nil {
		return models.FingerprintMatch{}
	}

	_, err = fmt.Fprintf(
		conn,
		"GET / HTTP/1.0\r\n"+
			"Host: %s\r\n"+
			"User-Agent: ipspect\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		ip,
	)

	if err != nil {
		return models.FingerprintMatch{}
	}

	reader := bufio.NewReader(
		io.LimitReader(
			conn,
			32<<10,
		),
	)

	resp, err := http.ReadResponse(
		reader,
		&http.Request{
			Method: "GET",
		},
	)

	if err != nil {
		return models.FingerprintMatch{}
	}

	defer resp.Body.Close()

	// An HTTPS-only server may return a
	// plaintext HTTP 400 diagnostic.
	// This does not confirm HTTP service.
	if !secure &&
		resp.StatusCode == http.StatusBadRequest {

		body, _ := io.ReadAll(
			io.LimitReader(
				resp.Body,
				512,
			),
		)

		lower := strings.ToLower(
			string(body),
		)

		if strings.Contains(
			lower,
			"http request to an https server",
		) ||
			strings.Contains(
				lower,
				"plain http request was sent to https port",
			) {

			return models.FingerprintMatch{}
		}
	}

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
		Service: service,

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
