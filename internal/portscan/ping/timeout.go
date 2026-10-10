package ping

import "time"

func (s *scanState) expireProbes(
	now time.Time,
) {
	for seq, pending := range s.pending {
		if now.Before(
			pending.deadline,
		) {
			continue
		}

		if pending.attempts <= icmpRetries {
			pending.attempts++

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
