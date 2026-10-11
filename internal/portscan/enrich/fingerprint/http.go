package fingerprint

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"ipspect/internal/models"
	"net"
	"strconv"
	"strings"
	"time"
)

const probeTimeout = 500 * time.Millisecond

func probeHTTP(
	ip string,
	port int,
	secure bool,
) (models.FingerprintResult, string) {
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
		return models.FingerprintResult{}, ""
	}

	defer conn.Close()

	if err := conn.SetDeadline(
		time.Now().Add(probeTimeout),
	); err != nil {
		return models.FingerprintResult{}, ""
	}

	_, err = fmt.Fprintf(
		conn,
		"GET / HTTP/1.0\r\n"+
			"Host: %s\r\n"+
			"User-Agent: ipspect\r\n"+
			"Connection: close\r\n\r\n",
		ip,
	)

	if err != nil {
		return models.FingerprintResult{}, ""
	}

	reader := bufio.NewReader(conn)

	line, err := reader.ReadString('\n')

	if err != nil {
		return models.FingerprintResult{}, ""
	}

	banner := strings.TrimSpace(line)

	if !strings.HasPrefix(
		strings.ToUpper(banner),
		"HTTP/",
	) {
		return models.FingerprintResult{}, ""
	}

	service := "http"
	evidence := "HTTP response to active request"

	if secure {
		service = "https"
		evidence = "HTTP response over TLS"
	}

	return models.FingerprintResult{
		Service:    service,
		Confidence: "high",
		Evidence:   evidence,
	}, banner
}
