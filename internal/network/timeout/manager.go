package timeout

import (
	"sync"
	"time"
)

type Mode string

const (
	TCP  Mode = "tcp"
	ICMP Mode = "icmp"
	ARP  Mode = "arp"
)

type policy struct {
	initial time.Duration
	minimum time.Duration
	maximum time.Duration
	warmup  int
}

func policyFor(mode Mode) policy {
	switch mode {
	case TCP:
		return policy{
			7 * time.Second,
			750 * time.Millisecond,
			12 * time.Second,
			4,
		}

	case ICMP:
		return policy{
			1500 * time.Millisecond,
			500 * time.Millisecond,
			8 * time.Second,
			4,
		}

	case ARP:
		return policy{
			1250 * time.Millisecond,
			350 * time.Millisecond,
			5 * time.Second,
			4,
		}

	default:
		return policy{
			2 * time.Second,
			750 * time.Millisecond,
			10 * time.Second,
			4,
		}
	}
}

type key struct {
	mode  Mode
	scope string
}

type Manager struct {
	mu sync.RWMutex

	estimates     map[key]*estimate
	modeEstimates map[Mode]*estimate
}

func New() *Manager {
	return &Manager{
		estimates: make(
			map[key]*estimate,
		),
		modeEstimates: make(
			map[Mode]*estimate,
		),
	}
}

func (m *Manager) Duration(
	mode Mode,
	scope string,
) time.Duration {
	p := policyFor(mode)

	m.mu.RLock()

	e := m.estimates[key{
		mode:  mode,
		scope: scope,
	}]

	// Use the mode-level estimate until
	// this target has enough samples.
	if e == nil || e.samples < p.warmup {
		e = m.modeEstimates[mode]
	}

	if e == nil {
		m.mu.RUnlock()
		return p.initial
	}

	duration := e.duration(p)

	m.mu.RUnlock()

	return duration
}

func (m *Manager) Observe(
	mode Mode,
	scope string,
	rtt time.Duration,
) {
	if rtt <= 0 {
		return
	}

	p := policyFor(mode)

	if rtt > p.maximum {
		rtt = p.maximum
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	k := key{
		mode:  mode,
		scope: scope,
	}

	e := m.estimates[k]

	if e == nil {
		e = &estimate{}
		m.estimates[k] = e
	}

	e.observe(rtt)

	// Also update the shared estimate
	// for this scanning mode.
	modeEstimate := m.modeEstimates[mode]

	if modeEstimate == nil {
		modeEstimate = &estimate{}
		m.modeEstimates[mode] = modeEstimate
	}

	modeEstimate.observe(rtt)
}
