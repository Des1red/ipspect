package search

import (
	"ipspect/internal/network/app"
	"time"
)

func (s *scanState) expireProbes(
	now time.Time,
) {
	for srcPort, pending := range s.pending {
		if now.Before(
			pending.deadline,
		) {
			continue
		}

		app.Timeout(app.TCP)

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
