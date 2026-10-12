package time

import (
	"fmt"
	"ipspect/internal/output"
	"sync"
	stdtime "time"
)

type Timer struct {
	Name  string
	Start stdtime.Time
	End   stdtime.Time
	Total stdtime.Duration
}

var (
	mu     sync.Mutex
	timers []*Timer
)

func New(
	name string,
) *Timer {
	timer := &Timer{
		Name:  name,
		Start: stdtime.Now(),
	}

	mu.Lock()
	timers = append(timers, timer)
	mu.Unlock()

	return timer
}

func (t *Timer) Stop() {
	mu.Lock()
	defer mu.Unlock()

	if !t.End.IsZero() {
		return
	}

	t.End = stdtime.Now()
	t.Total = t.End.Sub(t.Start)
}

func PrintTimes() {
	mu.Lock()

	snapshot := make(
		[]Timer,
		0,
		len(timers),
	)

	for _, timer := range timers {
		snapshot = append(snapshot, *timer)
	}

	mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	output.Log("stage", "Execution Times")

	for _, timer := range snapshot {
		start := timer.Start.Format("15:04:05.000")
		end := "running"
		total := stdtime.Since(timer.Start)

		if !timer.End.IsZero() {
			end = timer.End.Format("15:04:05.000")
			total = timer.Total
		}

		output.Log(
			"text",
			fmt.Sprintf(
				"%-24s  Start: %s  End: %-12s  Total: %s",
				timer.Name,
				start,
				end,
				total,
			),
		)
	}

	output.Log("end", "")
}
