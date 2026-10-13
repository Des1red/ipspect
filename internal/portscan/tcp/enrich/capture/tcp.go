package capture

import (
	"bytes"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"net"
	"strconv"
	"strings"
	"time"
)

const maxInitialResponse = 256

func Capture(
	ip string,
	detail *models.PortDetail,
) {
	address := net.JoinHostPort(
		ip,
		strconv.Itoa(detail.Port),
	)

	start := time.Now()

	app.Send(app.TCPConnect)

	conn, err := net.DialTimeout(
		"tcp",
		address,
		500*time.Millisecond,
	)

	detail.Latency = time.Since(start)

	if err != nil {
		app.TimeoutOnError(
			app.TCPConnect,
			err,
		)
		return
	}

	app.Receive(
		app.TCPConnect,
		detail.Latency,
	)

	defer conn.Close()

	if err := conn.SetReadDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	); err != nil {
		return
	}

	buffer := make(
		[]byte,
		maxInitialResponse,
	)

	n, _ := conn.Read(buffer)

	if n == 0 {
		return
	}

	detail.RawResponse = append(
		[]byte(nil),
		buffer[:n]...,
	)

	line := detail.RawResponse

	if index := bytes.IndexByte(
		line,
		'\n',
	); index >= 0 {
		line = line[:index]
	}

	if !isTextBanner(line) {
		return
	}

	detail.Banner = strings.TrimSpace(
		string(line),
	)
}

func isTextBanner(
	data []byte,
) bool {
	if len(data) == 0 {
		return false
	}

	for _, b := range data {
		if b == '\r' || b == '\t' {
			continue
		}

		if b < 0x20 || b > 0x7e {
			return false
		}
	}

	return true
}
