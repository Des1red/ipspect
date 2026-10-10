//go:build linux

package arp

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
)

func parseReply(
	frame []byte,
	localIP net.IP,
	localMAC net.HardwareAddr,
) (net.IP, net.HardwareAddr, bool) {
	if len(frame) < 42 ||
		binary.BigEndian.Uint16(
			frame[12:14],
		) != 0x0806 ||
		binary.BigEndian.Uint16(
			frame[14:16],
		) != 1 ||
		binary.BigEndian.Uint16(
			frame[16:18],
		) != 0x0800 ||
		frame[18] != 6 ||
		frame[19] != 4 ||
		binary.BigEndian.Uint16(
			frame[20:22],
		) != 2 ||
		!bytes.Equal(
			frame[38:42],
			localIP.To4(),
		) ||
		!bytes.Equal(
			frame[32:38],
			localMAC,
		) {

		return nil, nil, false
	}

	senderIP := net.IPv4(
		frame[28],
		frame[29],
		frame[30],
		frame[31],
	).To4()

	if senderIP.Equal(net.IPv4zero) {
		return nil, nil, false
	}

	senderMAC := append(
		net.HardwareAddr(nil),
		frame[22:28]...,
	)

	return senderIP, senderMAC, true
}

func (s *scanner) receiveLoop() {
	defer s.wg.Done()

	buf := make(
		[]byte,
		2048,
	)

	for {
		select {
		case <-s.done:
			return

		default:
		}

		n, _, err := syscall.Recvfrom(
			s.fd,
			buf,
			0,
		)

		if err != nil {
			if err == syscall.EINTR ||
				err == syscall.EAGAIN ||
				err == syscall.EWOULDBLOCK {

				continue
			}

			return
		}

		ip, mac, ok := parseReply(
			buf[:n],
			s.group.sourceIP,
			s.group.iface.HardwareAddr,
		)

		if !ok {
			continue
		}

		key := ip.String()

		if _, known := s.expected[key]; !known {
			continue
		}

		s.mu.Lock()

		s.found[key] = arpHost{
			ip: append(
				net.IP(nil),
				ip...,
			),

			mac: append(
				net.HardwareAddr(nil),
				mac...,
			),

			iface: s.group.iface.Name,
		}

		s.mu.Unlock()
	}
}

func (s *scanner) results() []arpHost {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(
		[]arpHost,
		0,
		len(s.found),
	)

	for _, host := range s.found {
		result = append(
			result,
			arpHost{
				ip: append(
					net.IP(nil),
					host.ip...,
				),

				mac: append(
					net.HardwareAddr(nil),
					host.mac...,
				),

				iface: host.iface,
			},
		)
	}

	return result
}
