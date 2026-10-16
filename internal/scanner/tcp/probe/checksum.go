package probe

import (
	"encoding/binary"
	"net"
)

func tcpChecksum(
	srcIP net.IP,
	dstIP net.IP,
	segment []byte,
) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()

	pseudo := make(
		[]byte,
		12+len(segment),
	)

	copy(
		pseudo[0:4],
		src,
	)

	copy(
		pseudo[4:8],
		dst,
	)

	pseudo[8] = 0
	pseudo[9] = 6

	binary.BigEndian.PutUint16(
		pseudo[10:12],
		uint16(len(segment)),
	)

	copy(
		pseudo[12:],
		segment,
	)

	return internetChecksum(
		pseudo,
	)
}

func internetChecksum(
	data []byte,
) uint16 {
	var sum uint32

	for len(data) >= 2 {
		sum += uint32(
			binary.BigEndian.Uint16(
				data[:2],
			),
		)

		data = data[2:]
	}

	if len(data) == 1 {
		sum += uint32(
			data[0],
		) << 8
	}

	for sum>>16 != 0 {
		sum =
			(sum & 0xffff) +
				(sum >> 16)
	}

	return ^uint16(sum)
}
