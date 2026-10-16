package icmp

import (
	"net"

	"ipspect/internal/network/app"
	"ipspect/internal/network/timeout"
)

func (s *scanState) handleReply(
	reply icmpReply,
) {
	pending, ok := s.pending[reply.seq]

	if !ok {
		return
	}

	if !pending.ip.Equal(reply.ip) {
		return
	}

	rtt := reply.receivedAt.Sub(
		pending.sentAt,
	)

	if pending.attempts == 1 && rtt >= 0 {
		s.timeouts.Observe(
			timeout.ICMP,
			pending.ip.String(),
			rtt,
		)

		app.Receive(
			app.ICMP,
			rtt,
		)
	} else {
		// The reply could belong to an
		// earlier transmission.
		// Count it, but do not sample RTT.
		app.Receive(
			app.ICMP,
			-1,
		)
	}

	key := pending.ip.String()

	if _, exists := s.live[key]; !exists {
		s.live[key] = append(
			net.IP(nil),
			pending.ip...,
		)
	}

	delete(
		s.pending,
		pending.seq,
	)

	delete(
		s.usedSequences,
		pending.seq,
	)
}
