package scanner

import (
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
)

type stageCounter struct {
	current int
	total   int
}

func newStageCounter() *stageCounter {
	stages := &stageCounter{}

	if models.ActiveEngines.ICMP {
		stages.total++
	}

	if models.ActiveEngines.ARP {
		stages.total++
	}

	if models.ActiveEngines.TCP {
		stages.total += 3
	}

	return stages
}

func (s *stageCounter) next(
	name string,
) {
	s.current++

	output.Log(
		"stage",
		fmt.Sprintf(
			"%02d / %02d  %s",
			s.current,
			s.total,
			name,
		),
	)
}
