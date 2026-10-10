package ping

import (
	"errors"
	"net"

	"golang.org/x/net/icmp"
)

func (s *icmpScanner) readLoop(
	conn *icmp.PacketConn,
	protocol int,
	replyType icmp.Type,
) {
	buffer := make(
		[]byte,
		1500,
	)

	for {
		n, peer, err :=
			conn.ReadFrom(buffer)

		if err != nil {
			if errors.Is(
				err,
				net.ErrClosed,
			) {
				return
			}

			return
		}

		peerIP, ok :=
			peer.(*net.IPAddr)

		if !ok {
			continue
		}

		message, err :=
			icmp.ParseMessage(
				protocol,
				buffer[:n],
			)

		if err != nil {
			continue
		}

		if message.Type != replyType {
			continue
		}

		echo, ok :=
			message.Body.(*icmp.Echo)

		if !ok {
			continue
		}

		if echo.ID != s.id {
			continue
		}

		s.replies <- icmpReply{
			ip: append(
				net.IP(nil),
				peerIP.IP...,
			),

			seq: echo.Seq,
		}
	}
}
