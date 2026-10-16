package sender

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"ipspect/internal/analyzer"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"net"
	"net/http"
	"strconv"
	"time"
)

const probeTimeout = 750 * time.Millisecond

func ProbeHTTP(
	ip string,
	port int,
	secure bool,
	engine *analyzer.Engine,
) models.FingerprintMatch {
	address := net.JoinHostPort(
		ip,
		strconv.Itoa(port),
	)

	dialer := &net.Dialer{
		Timeout: probeTimeout,
	}

	protocol := app.HTTP

	if secure {
		protocol = app.HTTPS
	}

	var conn net.Conn
	var err error

	connectStart := time.Now()

	app.Send(app.TCPConnect)

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
		app.Fail(app.TCPConnect, err)
		return models.FingerprintMatch{}
	}

	app.Receive(
		app.TCPConnect,
		time.Since(connectStart),
	)

	defer conn.Close()

	if err := conn.SetDeadline(
		time.Now().Add(probeTimeout),
	); err != nil {
		return models.FingerprintMatch{}
	}

	requestStart := time.Now()

	app.Send(protocol)

	written, err := fmt.Fprintf(
		conn,
		"GET / HTTP/1.0\r\n"+
			"Host: %s\r\n"+
			"User-Agent: ipspect\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		ip,
	)

	if err != nil {
		app.Fail(protocol, err)
		return models.FingerprintMatch{}
	}

	if written == 0 {
		app.Drop(protocol)
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
		app.Fail(protocol, err)
		return models.FingerprintMatch{}
	}

	app.Receive(
		protocol,
		time.Since(requestStart),
	)

	defer resp.Body.Close()

	// Reject plaintext HTTPS-only diagnostics.
	if !secure &&
		resp.StatusCode == http.StatusBadRequest {

		body, _ := io.ReadAll(
			io.LimitReader(
				resp.Body,
				512,
			),
		)

		if engine.IsHTTPSOnlyDiagnostic(body) {
			return models.FingerprintMatch{}
		}
	}

	return engine.IdentifyHTTPResponse(
		resp,
		secure,
	)
}
