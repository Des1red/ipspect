//go:build linux

package arp

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

func networkOrder(
	value uint16,
) uint16 {
	var b [2]byte

	binary.BigEndian.PutUint16(
		b[:],
		value,
	)

	return binary.NativeEndian.Uint16(
		b[:],
	)
}

func openScanner(
	group interfaceGroup,
) (*scanner, error) {
	protocol := networkOrder(
		syscall.ETH_P_ARP,
	)

	fd, err := syscall.Socket(
		syscall.AF_PACKET,
		syscall.SOCK_RAW|syscall.SOCK_CLOEXEC,
		int(protocol),
	)

	if err != nil {
		return nil, fmt.Errorf(
			"open ARP socket: %w",
			err,
		)
	}

	err = syscall.Bind(
		fd,
		&syscall.SockaddrLinklayer{
			Ifindex:  group.iface.Index,
			Protocol: protocol,
		},
	)

	if err != nil {
		syscall.Close(fd)

		return nil, fmt.Errorf(
			"bind ARP socket to %s: %w",
			group.iface.Name,
			err,
		)
	}

	err = syscall.SetsockoptTimeval(
		fd,
		syscall.SOL_SOCKET,
		syscall.SO_RCVTIMEO,
		&syscall.Timeval{
			Sec:  0,
			Usec: 200000,
		},
	)

	if err != nil {
		syscall.Close(fd)

		return nil, fmt.Errorf(
			"set ARP socket timeout: %w",
			err,
		)
	}

	s := &scanner{
		fd:    fd,
		group: group,

		expected: make(
			map[string]struct{},
			len(group.targets),
		),

		found: make(
			map[string]arpHost,
		),

		done: make(
			chan struct{},
		),
	}

	for _, ip := range group.targets {
		s.expected[ip.String()] =
			struct{}{}
	}

	s.wg.Add(1)

	go s.receiveLoop()

	return s, nil
}

func (s *scanner) close() {
	close(s.done)

	s.wg.Wait()

	syscall.Close(s.fd)
}
