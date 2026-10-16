package search

import (
	"fmt"
	"time"

	"ipspect/internal/models"
)

func (s *scanState) dispatch() error {
	for s.moreJobs &&
		len(s.pending) < synWindow {

		job := scanJob{
			hostIndex: s.hostIndex,

			ip: models.INFO.
				Targets[s.hostIndex].
				To4(),

			port: s.ports[s.portIndex],
		}

		if job.ip == nil {
			s.advanceCursor()
			continue
		}

		srcIP, err := s.scanner.SourceIPv4(
			job.ip,
		)

		if err != nil {
			return fmt.Errorf(
				"determine TCP source for %s: %w",
				job.ip,
				err,
			)
		}

		srcPort, err :=
			s.scanner.ReserveSourcePort(
				s.usedPorts,
			)

		if err != nil {
			return fmt.Errorf(
				"reserve SYN source port: %w",
				err,
			)
		}

		seq := s.scanner.Sequence()
		sentAt := time.Now()

		err = s.scanner.SendSYN(
			srcIP,
			job.ip,
			srcPort,
			uint16(job.port),
			seq,
		)

		if err != nil {
			if s.recoverableSendError(err) {
				return nil
			}

			return fmt.Errorf(
				"send SYN to %s:%d: %w",
				job.ip,
				job.port,
				err,
			)
		}

		s.consecutiveSendFailures = 0

		wait := s.probeTimeout(
			job.ip,
			0,
		)

		s.pending[srcPort] = &pendingProbe{
			job:     job,
			srcIP:   srcIP,
			srcPort: srcPort,
			seq:     seq,

			attempts: 1,

			sentAt:   sentAt,
			deadline: sentAt.Add(wait),
		}

		s.usedPorts[srcPort] = struct{}{}

		s.advanceCursor()

		// Only one successful transmission
		// per scheduler tick.
		return nil
	}

	return nil
}
