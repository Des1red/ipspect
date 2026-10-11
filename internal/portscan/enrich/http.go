package enrich

import (
	"bufio"
	"crypto/tls"
	"ipspect/internal/models"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func enrichConfirmedHTTP() {
	const workers = 32

	jobs := make(
		chan enrichJob,
		workers,
	)

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for job := range jobs {
				host := &models.LOOT.Hosts[job.hostIndex]
				detail := &host.Details[job.detailIndex]

				enrichHTTP(
					host.Target,
					detail,
					detail.Fingerprint.Service,
				)
			}
		}()
	}

	for h := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[h]

		for i := range host.Details {
			detail := &host.Details[i]

			if detail.State != "open" ||
				detail.Fingerprint.Confidence != "high" {
				continue
			}

			service := detail.Fingerprint.Service

			if service != "http" &&
				service != "https" {
				continue
			}

			jobs <- enrichJob{
				hostIndex:   h,
				detailIndex: i,
			}
		}
	}

	close(jobs)
	wg.Wait()
}

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
