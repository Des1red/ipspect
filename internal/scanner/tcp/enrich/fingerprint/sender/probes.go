package sender

import (
	"crypto/tls"
	"ipspect/internal/analyzer"
	"ipspect/internal/network/app"
	"net"
	"strconv"
	"time"
)

func ProbeRaw(
	ip string,
	port int,
	request analyzer.Probe,
) []byte {
	address := net.JoinHostPort(
		ip,
		strconv.Itoa(port),
	)

	dialer := &net.Dialer{
		Timeout: probeTimeout,
	}

	start := time.Now()

	app.Send(app.TCPConnect)

	var conn net.Conn
	var err error

	if request.TLS {
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
		return nil
	}

	app.Receive(
		app.TCPConnect,
		time.Since(start),
	)

	defer conn.Close()

	if err := conn.SetDeadline(
		time.Now().Add(probeTimeout),
	); err != nil {
		return nil
	}

	if len(request.Payload) > 0 {
		n, err := conn.Write(
			request.Payload,
		)

		if err != nil ||
			n != len(request.Payload) {
			return nil
		}
	}

	buffer := make(
		[]byte,
		request.ReadSize,
	)

	n, _ := conn.Read(buffer)

	if n == 0 {
		return nil
	}

	return append(
		[]byte(nil),
		buffer[:n]...,
	)
}
