package capture

import (
	"bytes"
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"ipspect/internal/output"
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

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.capture [%s]: connecting timeout=500ms",
			address,
		),
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
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.capture [%s]: connection failed latency=%s error=%v",
				address,
				detail.Latency,
				err,
			),
		)

		app.Fail(app.TCPConnect, err)
		return
	}

	app.Receive(
		app.TCPConnect,
		detail.Latency,
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.capture [%s]: connected latency=%s",
			address,
			detail.Latency,
		),
	)

	defer conn.Close()

	if err := conn.SetReadDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	); err != nil {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.capture [%s]: setting read deadline failed error=%v",
				address,
				err,
			),
		)

		return
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.capture [%s]: reading initial response buffer=%d timeout=500ms",
			address,
			maxInitialResponse,
		),
	)

	buffer := make(
		[]byte,
		maxInitialResponse,
	)

	n, readErr := conn.Read(buffer)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.capture [%s]: read completed bytes=%d error=%v",
			address,
			n,
			readErr,
		),
	)

	if n == 0 {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.capture [%s]: no initial response captured",
				address,
			),
		)

		return
	}

	detail.RawResponse = append(
		[]byte(nil),
		buffer[:n]...,
	)

	preview := detail.RawResponse

	if len(preview) > 32 {
		preview = preview[:32]
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.capture [%s]: stored raw response bytes=%d hex_preview=% X",
			address,
			len(detail.RawResponse),
			preview,
		),
	)

	line := detail.RawResponse

	if index := bytes.IndexByte(
		line,
		'\n',
	); index >= 0 {
		line = line[:index]
	}

	if !isTextBanner(line) {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.capture [%s]: no text banner extracted; retaining raw response for binary analysis",
				address,
			),
		)

		return
	}

	detail.Banner = strings.TrimSpace(
		string(line),
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.capture [%s]: text banner extracted=%q",
			address,
			detail.Banner,
		),
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
