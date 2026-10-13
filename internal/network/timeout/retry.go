package timeout

import "time"

func (m *Manager) Backoff(
	mode Mode,
	scope string,
	retry int,
) time.Duration {
	duration := m.Duration(
		mode,
		scope,
	)

	maximum := policyFor(mode).maximum

	for i := 0; i < retry; i++ {
		if duration >= maximum/2 {
			return maximum
		}

		duration *= 2
	}

	if duration > maximum {
		return maximum
	}

	return duration
}
