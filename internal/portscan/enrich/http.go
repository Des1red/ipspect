package enrich

import (
	"bufio"
	"crypto/tls"
	"ipspect/internal/models"
	"net"
	"strconv"
	"strings"
	"time"
)

func enrichHTTP(
	ip string,
	detail *models.PortDetail,
	service string,
) {
	address := net.JoinHostPort(
		ip,
		strconv.Itoa(detail.Port),
	)

	start := time.Now()

	conn, err := openHTTPConnection(
		address,
		service,
	)

	detail.Latency =
		time.Since(start)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.SetWriteDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	)

	_, err = conn.Write(
		[]byte(
			"GET / HTTP/1.0\r\n" +
				"Host: " + ip + "\r\n" +
				"User-Agent: ipspect\r\n" +
				"Connection: close\r\n" +
				"\r\n",
		),
	)

	if err != nil {
		return
	}

	conn.SetReadDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	)

	reader := bufio.NewReader(
		conn,
	)

	line, err := reader.ReadString(
		'\n',
	)

	if err != nil {
		return
	}

	detail.Banner =
		strings.TrimSpace(line)

	detail.Headers =
		grabHeaders(reader)
}

func openHTTPConnection(
	address string,
	service string,
) (net.Conn, error) {
	if service == "https" {
		return tls.DialWithDialer(
			&net.Dialer{
				Timeout: 500 * time.Millisecond,
			},
			"tcp",
			address,
			&tls.Config{
				InsecureSkipVerify: true,
			},
		)
	}

	return net.DialTimeout(
		"tcp",
		address,
		500*time.Millisecond,
	)
}
