package search

import "time"

func (s *scanState) expireProbes(
	now time.Time,
) {
	for srcPort, pending := range s.pending {
		if now.Before(
			pending.deadline,
		) {
			continue
		}

		recordPortState(
			pending.job.hostIndex,
			pending.job.port,
			"filtered",
		)

		s.releaseProbe(
			srcPort,
		)
	}
}
