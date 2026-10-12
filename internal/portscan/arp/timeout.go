package arp

import (
	"ipspect/internal/network/app"
)

func (s *scanner) recordTimeouts() {
	s.mu.Lock()

	unanswered := 0

	for ip := range s.expected {
		if _, exists := s.found[ip]; exists {
			continue
		}

		unanswered++
	}

	s.mu.Unlock()

	for i := 0; i < unanswered; i++ {
		app.Timeout(app.ARP)
	}
}
