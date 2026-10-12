package ping

import (
	"ipspect/internal/network/app"
	"time"
)

func (s *scanState) expireProbes(
	now time.Time,
) {
	for seq, pending := range s.pending {
		if now.Before(
			pending.deadline,
		) {
			continue
		}

		if !pending.sentAt.IsZero() {
			app.Timeout(app.ICMP)

			pending.sentAt = time.Time{}
		}

		if pending.attempts <= icmpRetries {
			pending.attempts++

			sentAt := time.Now()

			err := s.scanner.send(
				pending.ip,
				pending.seq,
			)

			pending.deadline = now.Add(
				icmpTimeout,
			)

			if err != nil {
				continue
			}

			pending.sentAt = sentAt

			continue
		}

		delete(
			s.pending,
			seq,
		)

		delete(
			s.usedSequences,
			seq,
		)
	}
}
