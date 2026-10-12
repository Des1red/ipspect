package app

import "time"

func Snapshot() NetworkStats {
	now := time.Now()

	icmp, _, _ := snapshotAt(ICMP, now)
	arp, _, _ := snapshotAt(ARP, now)
	tcp, _, _ := snapshotAt(TCP, now)

	return NetworkStats{
		ICMP: icmp,
		ARP:  arp,
		TCP:  tcp,
	}
}

func snapshotAt(
	protocol Protocol,
	now time.Time,
) (ProtocolStats, bool, bool) {
	state := stateFor(protocol)

	if state == nil {
		return ProtocolStats{}, false, false
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	stats := state.stats

	if state.started.IsZero() {
		return stats, false, false
	}

	end := now

	if !state.stopped.IsZero() {
		end = state.stopped
	}

	seconds := end.Sub(
		state.started,
	).Seconds()

	if seconds > 0 {
		stats.TransmissionRate =
			float64(stats.Sent) / seconds
	}

	return stats, true, state.rttSamples > 0
}
