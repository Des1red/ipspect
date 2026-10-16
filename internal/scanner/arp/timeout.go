package arp

import (
	"ipspect/internal/network/app"
	"net"
	"time"
)

func (s *scanner) hasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.expected) > 0
}

func (s *scanner) expireProbes(
	now time.Time,
) []net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()

	var retries []net.IP

	for ip, pending := range s.expected {
		if pending.queued ||
			now.Before(pending.deadline) {

			continue
		}

		if pending.retries >= arpRetries {
			delete(
				s.expected,
				ip,
			)

			s.missed++

			continue
		}

		pending.queued = true

		retries = append(
			retries,
			net.ParseIP(ip).To4(),
		)
	}

	return retries
}

func (s *scanner) recordTimeouts() {
	s.mu.Lock()

	unanswered := s.missed

	s.mu.Unlock()

	for i := 0; i < unanswered; i++ {
		app.Timeout(app.ARP)
	}
}
