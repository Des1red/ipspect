package probe

import (
	"fmt"
	"net"

	"ipspect/internal/network/app"

	"golang.org/x/net/ipv4"
)

func (s *SYNScanner) SendSYN(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
) error {
	return s.sendSYN(
		srcIP,
		dstIP,
		srcPort,
		dstPort,
		seq,
		false,
	)
}

func (s *SYNScanner) RetrySYN(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
) error {
	return s.sendSYN(
		srcIP,
		dstIP,
		srcPort,
		dstPort,
		seq,
		true,
	)
}

func (s *SYNScanner) sendSYN(
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	seq uint32,
	retry bool,
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

	if err := s.sendSegment(
		srcIP,
		dstIP,
		segment,
	); err != nil {
		return err
	}

	if retry {
		app.Retry(app.TCP)
	} else {
		app.Send(app.TCP)
	}

	return nil
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
