package search

import (
	"fmt"
	"ipspect/internal/models"
	"time"
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

		s.advanceCursor()

		if job.ip == nil {
			continue
		}

		srcIP, err :=
			s.scanner.SourceIPv4(
				job.ip,
			)

		if err != nil {
			recordPortState(
				job.hostIndex,
				job.port,
				"filtered",
			)

			continue
		}

		srcPort, err :=
			s.scanner.ReserveSourcePort(
				s.usedPorts,
			)

		if err != nil {
			return fmt.Errorf(
				"failed to reserve SYN source port: %w",
				err,
			)
		}

		seq := s.scanner.Sequence()

		pending := &pendingProbe{
			job:     job,
			srcIP:   srcIP,
			srcPort: srcPort,
			seq:     seq,

			deadline: time.Now().Add(
				synTimeout,
			),
		}

		err = s.scanner.SendSYN(
			srcIP,
			job.ip,
			srcPort,
			uint16(job.port),
			seq,
		)

		if err != nil {
			recordPortState(
				job.hostIndex,
				job.port,
				"filtered",
			)

			continue
		}

		s.pending[srcPort] =
			pending

		s.usedPorts[srcPort] =
			struct{}{}
	}

	return nil
}
