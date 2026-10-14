package ping

import (
	"fmt"
	"time"

	"ipspect/internal/network/app"
	"ipspect/internal/network/timeout"
)

func (s *scanState) expireProbes(
	now time.Time,
) {
	for seq, pending := range s.pending {
		if now.Before(pending.deadline) {
			continue
		}

		if pending.attempts <= icmpRetries {
			continue
		}

		app.Timeout(app.ICMP)

		delete(s.pending, seq)
		delete(s.usedSequences, seq)
	}
}

func (s *scanState) retryDue(
	now time.Time,
) (bool, error) {
	var pending *icmpProbe

	for _, candidate := range s.pending {
		if now.Before(candidate.deadline) ||
			candidate.attempts > icmpRetries {
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
		err = s.scanner.send(
			pending.ip,
			pending.seq,
			true,
		)
	}

	if err != nil {
		if s.recoverableSendError(err) {
			return true, nil
		}

		return true, fmt.Errorf(
			"retry ICMP to %s: %w",
			pending.ip,
			err,
		)
	}

	s.consecutiveSendFailures = 0

	pending.attempts++

	wait := s.timeouts.Backoff(
		timeout.ICMP,
		pending.ip.String(),
		pending.attempts-1,
	)

	pending.sentAt = sentAt
	pending.deadline = sentAt.Add(wait)

	return true, nil
}
