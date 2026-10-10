package probe

import "fmt"

func (s *SYNScanner) ReserveSourcePort(
	used map[uint16]struct{},
) (uint16, error) {
	const (
		first = uint16(49152)
		last  = uint16(65535)
	)

	for attempts := 0; attempts <= int(last-first); attempts++ {

		port := s.nextPort

		if s.nextPort == last {
			s.nextPort = first
		} else {
			s.nextPort++
		}

		if _, exists := used[port]; exists {
			continue
		}

		return port, nil
	}

	return 0, fmt.Errorf(
		"no source TCP port available",
	)
}

func (s *SYNScanner) Sequence() uint32 {
	s.nextSeq += 0x9e3779b9

	return s.nextSeq
}
