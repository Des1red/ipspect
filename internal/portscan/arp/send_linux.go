//go:build linux

package arp

import (
	"encoding/binary"
	"net"
	"syscall"
)

func buildRequest(
	sourceMAC net.HardwareAddr,
	sourceIP net.IP,
	targetIP net.IP,
) []byte {
	frame := make(
		[]byte,
		42,
	)

	// Ethernet broadcast address.
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}

	copy(
		frame[6:12],
		sourceMAC,
	)

	// Ethernet type: ARP.
	binary.BigEndian.PutUint16(
		frame[12:14],
		0x0806,
	)

	// Hardware type: Ethernet.
	binary.BigEndian.PutUint16(
		frame[14:16],
		1,
	)

	// Protocol type: IPv4.
	binary.BigEndian.PutUint16(
		frame[16:18],
		0x0800,
	)

	frame[18] = 6
	frame[19] = 4

	// Operation: request.
	binary.BigEndian.PutUint16(
		frame[20:22],
		1,
	)

	copy(
		frame[22:28],
		sourceMAC,
	)

	copy(
		frame[28:32],
		sourceIP.To4(),
	)

	// Target hardware address stays zero.

	copy(
		frame[38:42],
		targetIP.To4(),
	)

	return frame
}

func (s *scanner) send(
	target net.IP,
) error {
	frame := buildRequest(
		s.group.iface.HardwareAddr,
		s.group.sourceIP,
		target,
	)

	return syscall.Sendto(
		s.fd,
		frame,
		0,
		&syscall.SockaddrLinklayer{
			Ifindex: s.group.iface.Index,

			Protocol: networkOrder(
				syscall.ETH_P_ARP,
			),

			Halen: 6,

			Addr: [8]uint8{
				255, 255, 255,
				255, 255, 255,
			},
		},
	)
}
