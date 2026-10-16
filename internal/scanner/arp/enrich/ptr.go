package enrich

import (
	"context"
	"errors"
	"ipspect/internal/network/app"
	"net"
	"strings"
	"time"
)

const nameTimeout = 750 * time.Millisecond

func lookupPTR(ip string) string {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		nameTimeout,
	)
	defer cancel()

	start := time.Now()

	app.Send(app.DNS)

	names, err := net.DefaultResolver.LookupAddr(
		ctx,
		ip,
	)

	elapsed := time.Since(start)

	if err == nil {
		app.Receive(
			app.DNS,
			elapsed,
		)
	} else {
		var dnsErr *net.DNSError
		var netErr net.Error

		switch {
		case errors.Is(
			ctx.Err(),
			context.DeadlineExceeded,
		):
			app.Timeout(app.DNS)

		case errors.As(err, &netErr) &&
			netErr.Timeout():
			app.Timeout(app.DNS)

		case errors.As(err, &dnsErr) &&
			dnsErr.IsNotFound:
			app.Receive(
				app.DNS,
				elapsed,
			)
		}
	}

	if err != nil || len(names) == 0 {
		return ""
	}

	return strings.TrimSuffix(
		strings.TrimSpace(names[0]),
		".",
	)
}
