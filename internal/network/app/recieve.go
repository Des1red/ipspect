package app

import "time"

func Receive(
	protocol Protocol,
	rtt time.Duration,
) {
	state := stateFor(protocol)

	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if !state.canRecord() {
		return
	}

	state.stats.Received++

	if rtt < 0 {
		return
	}

	state.rttSamples++
	state.rttTotal += rtt

	stats := &state.stats.RTT

	if state.rttSamples == 1 {
		stats.Minimum = rtt
		stats.Maximum = rtt
		stats.Average = rtt

		return
	}

	if rtt < stats.Minimum {
		stats.Minimum = rtt
	}

	if rtt > stats.Maximum {
		stats.Maximum = rtt
	}

	stats.Average =
		state.rttTotal /
			time.Duration(state.rttSamples)
}
