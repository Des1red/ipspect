package ping

import "time"

func (s *scanState) run() {
	ticker := time.NewTicker(
		25 * time.Millisecond,
	)

	defer ticker.Stop()

	for s.nextTarget < s.total ||
		len(s.pending) > 0 {

		s.dispatch()

		if len(s.pending) == 0 {
			continue
		}

		select {
		case reply := <-s.scanner.replies:
			s.handleReply(reply)

		case <-ticker.C:
			s.expireProbes(
				time.Now(),
			)
		}
	}
}
