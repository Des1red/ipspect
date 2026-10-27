package sender

import (
	"crypto/tls"
	"ipspect/internal/analyzer"
	"ipspect/internal/network/app"
	"net"
	"strconv"
	"time"
)

func ProbeRaw(ip string, port int, request analyzer.Probe) []byte {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: probeTimeout}

	start := time.Now()
	app.Send(app.TCPConnect)

	var conn net.Conn
	var err error

	if request.TLS {
		conn, err = tls.DialWithDialer(
			dialer,
			"tcp",
			address,
			&tls.Config{InsecureSkipVerify: true},
		)
	} else {
		conn, err = dialer.Dial("tcp", address)
	}

	if err != nil {
		app.Fail(app.TCPConnect, err)
		return nil
	}

	app.Receive(app.TCPConnect, time.Since(start))
	defer conn.Close()

	deadline := time.Now().Add(probeTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil
	}

	if len(request.Exchanges) == 0 {
		if !writeProbe(conn, request.Payload) {
			return nil
		}
		return readProbe(conn, request.ReadSize, deadline)
	}

	response := make([]byte, 0, 4096)

	for _, exchange := range request.Exchanges {
		if !writeProbe(conn, exchange.Payload) {
			return response
		}

		remaining := 8192 - len(response)
		if remaining <= 0 {
			break
		}

		readSize := exchange.ReadSize
		if readSize > remaining {
			readSize = remaining
		}

		response = append(
			response,
			readProbe(conn, readSize, deadline)...,
		)
	}

	return response
}

func writeProbe(conn net.Conn, payload []byte) bool {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil || n == 0 {
			return false
		}
		payload = payload[n:]
	}

	return true
}

func readProbe(conn net.Conn, size int, deadline time.Time) []byte {
	if size <= 0 {
		size = 1024
	}

	buffer := make([]byte, size)
	n, err := conn.Read(buffer)
	if n == 0 {
		return nil
	}

	for err == nil && n < len(buffer) {
		idleDeadline := time.Now().Add(50 * time.Millisecond)
		if idleDeadline.After(deadline) {
			idleDeadline = deadline
		}

		if err := conn.SetReadDeadline(idleDeadline); err != nil {
			break
		}

		var read int
		read, err = conn.Read(buffer[n:])
		n += read
	}

	_ = conn.SetReadDeadline(deadline)
	return buffer[:n]
}
