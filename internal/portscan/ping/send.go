package ping

import (
	"fmt"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func (s *icmpScanner) send(
	ip net.IP,
	seq int,
) error {
	var conn *icmp.PacketConn
	var typ icmp.Type

	if ip.To4() != nil {
		conn = s.v4
		typ = ipv4.ICMPTypeEcho
	} else {
		conn = s.v6
		typ = ipv6.ICMPTypeEchoRequest
	}

	if conn == nil {
		return fmt.Errorf(
			"no ICMP socket available for %s",
			ip,
		)
	}

	msg := icmp.Message{
		Type: typ,
		Code: 0,

		Body: &icmp.Echo{
			ID:  s.id,
			Seq: seq,

			Data: []byte(
				"ipspect",
			),
		},
	}

	packet, err := msg.Marshal(nil)

	if err != nil {
		return err
	}

	_, err = conn.WriteTo(
		packet,
		&net.IPAddr{
			IP: ip,
		},
	)

	return err
}
