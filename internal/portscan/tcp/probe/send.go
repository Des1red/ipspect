package probe

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
)

func (s *SYNScanner) SendSYN(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
) error {
	segment := buildTCPSegment(
		srcIP,
		dstIP,
		srcPort,
		dstPort,
		seq,
		0,
		FlagSYN,
	)

	return s.sendSegment(
		srcIP,
		dstIP,
		segment,
	)
}

func (s *SYNScanner) SendRST(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
) error {
	segment := buildTCPSegment(
		srcIP,
		dstIP,
		srcPort,
		dstPort,
		seq,
		0,
		FlagRST,
	)

	return s.sendSegment(
		srcIP,
		dstIP,
		segment,
	)
}

func (s *SYNScanner) sendSegment(
	srcIP net.IP,
	dstIP net.IP,
	segment []byte,
) error {
	header := &ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      0,
		TotalLen: 20 + len(segment),
		ID:       0,
		FragOff:  0,
		TTL:      64,
		Protocol: 6,
		Checksum: 0,
		Src:      srcIP,
		Dst:      dstIP,
	}

	if err := s.raw.WriteTo(
		header,
		segment,
		nil,
	); err != nil {

		return fmt.Errorf(
			"send raw TCP segment to %s: %w",
			dstIP,
			err,
		)
	}

	return nil
}
