package enrich

import (
	"bufio"
	"ipspect/internal/models"
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

	conn, err := net.DialTimeout(
		"tcp",
		address,
		500*time.Millisecond,
	)

	detail.Latency =
		time.Since(start)

	if err != nil {
		return
	}

	defer conn.Close()

	conn.SetReadDeadline(
		time.Now().Add(
			500 * time.Millisecond,
		),
	)

	reader := bufio.NewReader(
		conn,
	)

	line, _ := reader.ReadString(
		'\n',
	)

	detail.Banner =
		strings.TrimSpace(line)
}
