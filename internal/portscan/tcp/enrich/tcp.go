package enrich

import (
	"bufio"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"net"
	"strconv"
	"strings"
	"time"
)

func enrichTCP(
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

	conn.SetReadDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	)

	reader := bufio.NewReader(conn)

	line, _ := reader.ReadString('\n')

	detail.Banner = strings.TrimSpace(line)
}
