package app

import "time"

func Start(
	protocol Protocol,
) {
	state := stateFor(protocol)

	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	state.stats = ProtocolStats{}

	state.rttSamples = 0
	state.rttTotal = 0

	state.started = time.Now()
	state.stopped = time.Time{}
}

func Stop(
	protocol Protocol,
) {
	state := stateFor(protocol)

	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.started.IsZero() ||
		!state.stopped.IsZero() {
		return
	}

	state.stopped = time.Now()
}

func Reset() {
	for _, protocol := range []Protocol{
		ICMP,
		ARP,
		TCP,
	} {
		state := stateFor(protocol)

		state.mu.Lock()

		state.stats = ProtocolStats{}

		state.rttSamples = 0
		state.rttTotal = 0

		state.started = time.Time{}
		state.stopped = time.Time{}

		state.mu.Unlock()
	}
}

func (state *protocolState) canRecord() bool {
	if !state.stopped.IsZero() {
		return false
	}

	if state.started.IsZero() {
		state.started = time.Now()
	}

	return true
}
