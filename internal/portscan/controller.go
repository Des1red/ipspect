package portscan

import (
	"ipspect/internal/models"
	"ipspect/internal/output"
)

func Run() {
	stages := newStageCounter()

	if models.ActiveEngines.ICMP {
		runICMP(stages)
	}

	if models.ActiveEngines.ARP {
		runARP(stages)
	}

	if models.ActiveEngines.TCP {
		runTCP(stages)
	}

	output.Log("end", "")
}
