package probe

import (
	"fmt"
	"net"
)

func (s *SYNScanner) SourceIPv4(
	dst net.IP,
) (net.IP, error) {
	key := dst.String()

	s.sourceMu.Lock()

	if cached, ok :=
		s.sourceCache[key]; ok {

		ip := append(
			net.IP(nil),
			cached...,
		)

		s.sourceMu.Unlock()

		return ip, nil
	}

	s.sourceMu.Unlock()

	conn, err := net.DialUDP(
		"udp4",
		nil,
		&net.UDPAddr{
			IP:   dst,
			Port: 53,
		},
	)

	if err != nil {
		return nil, fmt.Errorf(
			"determine source IPv4 for %s: %w",
			dst,
			err,
		)
	}

	defer conn.Close()

	local, ok :=
		conn.LocalAddr().(*net.UDPAddr)

	if !ok {
		return nil, fmt.Errorf(
			"determine source IPv4 for %s",
			dst,
		)
	}

	src := local.IP.To4()

	if src == nil {
		return nil, fmt.Errorf(
			"no IPv4 source address for %s",
			dst,
		)
	}

	src = append(
		net.IP(nil),
		src...,
	)

	s.sourceMu.Lock()

	s.sourceCache[key] = src

	s.sourceMu.Unlock()

	return append(
		net.IP(nil),
		src...,
	), nil
}
