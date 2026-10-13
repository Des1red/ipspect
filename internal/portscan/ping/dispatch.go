package ping

import (
	"fmt"
	"net"
	"time"

	"ipspect/internal/models"
	"ipspect/internal/network/timeout"
)

func (s *scanState) dispatch() error {
	if s.nextTarget >= s.total ||
		len(s.pending) >= icmpWindow {
		return nil
	}

	ip := append(
		net.IP(nil),
		models.INFO.Targets[s.nextTarget]...,
	)

	seq, ok := reserveICMPSequence(
		&s.nextSequence,
		s.usedSequences,
	)

	if !ok {
		return fmt.Errorf(
			"no ICMP sequence available",
		)
	}

	sentAt := time.Now()

	err := s.scanner.send(
		ip,
		seq,
		false,
	)

	if err != nil {
		delete(s.usedSequences, seq)

		if s.recoverableSendError(err) {
			return nil
		}

		return fmt.Errorf(
			"send ICMP to %s: %w",
			ip,
			err,
		)
	}

	s.consecutiveSendFailures = 0

	wait := s.timeouts.Duration(
		timeout.ICMP,
		ip.String(),
	)

	s.pending[seq] = &icmpProbe{
		ip: ip,

		seq: seq,

		attempts: 1,

		sentAt:   sentAt,
		deadline: sentAt.Add(wait),
	}

	s.nextTarget++

	return nil
}
