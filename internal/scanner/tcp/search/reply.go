package search

import (
	"time"

	"ipspect/internal/network/app"
	"ipspect/internal/network/timeout"
	synprobe "ipspect/internal/scanner/tcp/probe"
)

func (s *scanState) handleReply(
	reply synprobe.Reply,
) {
	pending, ok := s.pending[reply.DstPort]

	if !ok {
		return
	}

	if !reply.SrcIP.Equal(
		pending.job.ip,
	) {
		return
	}

	if reply.SrcPort !=
		uint16(pending.job.port) {
		return
	}

	if reply.Flags&synprobe.FlagSYN != 0 &&
		reply.Flags&synprobe.FlagACK != 0 {

		if reply.Ack != pending.seq+1 {
			return
		}

		s.recordResponse(
			pending,
			reply.ReceivedAt,
		)

		recordPortState(
			pending.job.hostIndex,
			pending.job.port,
			"open",
		)

		_ = s.scanner.SendRST(
			pending.srcIP,
			pending.job.ip,
			pending.srcPort,
			uint16(pending.job.port),
			reply.Ack,
		)

		s.releaseProbe(pending.srcPort)
		return
	}

	if reply.Flags&synprobe.FlagRST != 0 {
		if reply.Flags&synprobe.FlagACK != 0 &&
			reply.Ack != pending.seq+1 {
			return
		}

		s.recordResponse(
			pending,
			reply.ReceivedAt,
		)

		recordPortState(
			pending.job.hostIndex,
			pending.job.port,
			"closed",
		)

		s.releaseProbe(pending.srcPort)
	}
}

func (s *scanState) recordResponse(
	pending *pendingProbe,
	receivedAt time.Time,
) {
	rtt := receivedAt.Sub(
		pending.sentAt,
	)

	if pending.attempts == 1 && rtt >= 0 {
		app.Receive(app.TCP, rtt)

		s.timeouts.Observe(
			timeout.TCP,
			pending.job.ip.String(),
			rtt,
		)

		return
	}

	// A reply following a retry may be
	// from either transmission.
	app.Receive(app.TCP, -1)
}

func (s *scanState) releaseProbe(
	srcPort uint16,
) {
	delete(s.pending, srcPort)
	delete(s.usedPorts, srcPort)
}
