package ping

import "net"

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
