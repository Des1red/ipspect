package search

import (
	"fmt"
	"time"
)

func (s *scanState) run() error {
	ticker := time.NewTicker(
		10 * time.Millisecond,
	)

	defer ticker.Stop()

	for s.moreJobs || len(s.pending) > 0 {
		if err := s.dispatch(); err != nil {
			return err
		}

		if len(s.pending) == 0 {
			continue
		}

		select {
		case reply := <-s.scanner.Replies():
			s.handleReply(reply)

		case <-ticker.C:
			s.expireProbes(
				time.Now(),
			)

		case err := <-s.scanner.Errors():
			if err != nil {
				return fmt.Errorf(
					"SYN receive error: %w",
					err,
				)
			}
		}
	}

	return nil
}
