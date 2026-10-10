package ping

import (
	"ipspect/internal/models"
	"net"
	"time"
)

func (s *scanState) dispatch() {
	for s.nextTarget < s.total &&
		len(s.pending) < icmpWindow {

		ip := append(
			net.IP(nil),
			models.INFO.Targets[s.nextTarget]...,
		)

		s.nextTarget++

		seq, ok := reserveICMPSequence(
			&s.nextSequence,
			s.usedSequences,
		)

		if !ok {
			break
		}

		pending := &icmpProbe{
			ip: ip,

			seq: seq,

			attempts: 1,

			deadline: time.Now().Add(
				icmpTimeout,
			),
		}

		err := s.scanner.send(
			pending.ip,
			pending.seq,
		)

		if err != nil {
			delete(
				s.usedSequences,
				seq,
			)

			continue
		}

		s.pending[seq] = pending
	}
}
