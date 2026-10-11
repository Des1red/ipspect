package enrich

import (
	"context"
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

	names, err := net.DefaultResolver.LookupAddr(
		ctx,
		ip,
	)

	if err != nil || len(names) == 0 {
		return ""
	}

	return strings.TrimSuffix(
		strings.TrimSpace(names[0]),
		".",
	)
}
