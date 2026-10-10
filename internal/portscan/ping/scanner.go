package ping

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func newICMPScanner(
	targets []net.IP,
) (*icmpScanner, error) {
	scanner := &icmpScanner{
		id: os.Getpid() & 0xffff,

		replies: make(
			chan icmpReply,
			2048,
		),
	}

	var needV4 bool
	var needV6 bool

	for _, ip := range targets {
		if ip.To4() != nil {
			needV4 = true
		} else {
			needV6 = true
		}
	}

	if needV4 {
		conn, err := icmp.ListenPacket(
			"ip4:icmp",
			"0.0.0.0",
		)

		if err != nil {
			return nil, fmt.Errorf(
				"open IPv4 ICMP socket: %w",
				err,
			)
		}

		scanner.v4 = conn

		go scanner.readLoop(
			conn,
			1,
			ipv4.ICMPTypeEchoReply,
		)
	}

	if needV6 {
		conn, err := icmp.ListenPacket(
			"ip6:ipv6-icmp",
			"::",
		)

		if err != nil {
			scanner.close()

			return nil, fmt.Errorf(
				"open IPv6 ICMP socket: %w",
				err,
			)
		}

		scanner.v6 = conn

		go scanner.readLoop(
			conn,
			58,
			ipv6.ICMPTypeEchoReply,
		)
	}

	return scanner, nil
}

func (s *icmpScanner) close() {
	if s.v4 != nil {
		s.v4.Close()
	}

	if s.v6 != nil {
		s.v6.Close()
	}
}
