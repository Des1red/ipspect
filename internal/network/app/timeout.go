package app

func Timeout(
	protocol Protocol,
) {
	state := stateFor(protocol)

	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.canRecord() {
		state.stats.TimedOut++
	}
}

func Drop(
	protocol Protocol,
) {
	state := stateFor(protocol)

	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	if state.canRecord() {
		state.stats.Dropped++
	}
}
