package timeout

import (
	"math"
	"time"
)

const clockGranularity = 10 * time.Millisecond

type estimate struct {
	samples int

	srtt      float64
	variation float64
}

func (e *estimate) observe(
	rtt time.Duration,
) {
	sample := float64(rtt)

	if e.samples == 0 {
		e.srtt = sample
		e.variation = sample / 2
	} else {
		e.variation =
			0.75*e.variation +
				0.25*math.Abs(
					e.srtt-sample,
				)

		e.srtt =
			0.875*e.srtt +
				0.125*sample
	}

	e.samples++
}

func (e *estimate) duration(
	p policy,
) time.Duration {
	if e.samples < p.warmup {
		return p.initial
	}

	value := time.Duration(
		e.srtt + math.Max(
			float64(clockGranularity),
			4*e.variation,
		),
	)

	if value < p.minimum {
		return p.minimum
	}

	if value > p.maximum {
		return p.maximum
	}

	return value
}
