package search

import (
	"fmt"
	"net"
	"time"

	"ipspect/internal/network/app"
	"ipspect/internal/network/timeout"
)

func (s *scanState) probeTimeout(
	ip net.IP,
	retry int,
) time.Duration {
	wait := s.timeouts.Backoff(
		timeout.TCP,
		ip.String(),
		retry,
	)

	minimum := synMinimumTimeout

	if retry > 0 {
		minimum *= 2
	}

	if wait < minimum {
		wait = minimum
	}

	return wait
}

func (s *scanState) expireProbes(
	now time.Time,
) {
	for srcPort, pending := range s.pending {
		if now.Before(pending.deadline) {
			continue
		}

		if pending.attempts <= synRetries {
			continue
		}

		app.Timeout(app.TCP)

		recordPortState(
			pending.job.hostIndex,
			pending.job.port,
			"filtered",
		)

		s.releaseProbe(srcPort)
	}
}

func (s *scanState) retryDue(
	now time.Time,
) (bool, error) {
	var pending *pendingProbe

	for _, candidate := range s.pending {
		if now.Before(candidate.deadline) ||
			candidate.attempts > synRetries {
			continue
		}

		if pending == nil ||
			candidate.deadline.Before(
				pending.deadline,
			) {
			pending = candidate
		}
	}

	if pending == nil {
		return false, nil
	}

	sentAt := time.Now()

	var err error

	if s.retrySend != nil {
		err = s.retrySend(pending)
	} else {
		err = s.scanner.RetrySYN(
			pending.srcIP,
			pending.job.ip,
			pending.srcPort,
			uint16(pending.job.port),
			pending.seq,
		)
	}

	if err != nil {
		if s.recoverableSendError(err) {
			return true, nil
		}

		return true, fmt.Errorf(
			"retry SYN to %s:%d: %w",
			pending.job.ip,
			pending.job.port,
			err,
		)
	}

	s.consecutiveSendFailures = 0
	pending.attempts++

	wait := s.probeTimeout(
		pending.job.ip,
		pending.attempts-1,
	)

	pending.sentAt = sentAt
	pending.deadline = sentAt.Add(wait)

	return true, nil
}
