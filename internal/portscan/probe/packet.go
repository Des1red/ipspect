package probe

import (
	"encoding/binary"
	"net"
)

const (
	FlagSYN byte = 0x02
	FlagRST byte = 0x04
	FlagACK byte = 0x10
)

func buildTCPSegment(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
	ack uint32,
	flags byte,
) []byte {
	segment := make(
		[]byte,
		20,
	)

	binary.BigEndian.PutUint16(
		segment[0:2],
		srcPort,
	)

	binary.BigEndian.PutUint16(
		segment[2:4],
		dstPort,
	)

	binary.BigEndian.PutUint32(
		segment[4:8],
		seq,
	)

	binary.BigEndian.PutUint32(
		segment[8:12],
		ack,
	)

	segment[12] = 5 << 4
	segment[13] = flags

	binary.BigEndian.PutUint16(
		segment[14:16],
		64240,
	)

	binary.BigEndian.PutUint16(
		segment[16:18],
		0,
	)

	binary.BigEndian.PutUint16(
		segment[18:20],
		0,
	)

	binary.BigEndian.PutUint16(
		segment[16:18],
		tcpChecksum(
			srcIP,
			dstIP,
			segment,
		),
	)

	return segment
}
