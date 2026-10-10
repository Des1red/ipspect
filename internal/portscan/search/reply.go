package search

import (
	synprobe "ipspect/internal/portscan/probe"
)

func (s *scanState) handleReply(
	reply synprobe.Reply,
) {
	pending, ok :=
		s.pending[reply.DstPort]

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

		s.releaseProbe(
			pending.srcPort,
		)

		return
	}

	if reply.Flags&synprobe.FlagRST != 0 {
		if reply.Flags&synprobe.FlagACK != 0 &&
			reply.Ack != pending.seq+1 {

			return
		}

		recordPortState(
			pending.job.hostIndex,
			pending.job.port,
			"closed",
		)

		s.releaseProbe(
			pending.srcPort,
		)
	}
}

func (s *scanState) releaseProbe(
	srcPort uint16,
) {
	delete(
		s.pending,
		srcPort,
	)

	delete(
		s.usedPorts,
		srcPort,
	)
}
