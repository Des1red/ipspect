package portscan

import (
	"ipspect/internal/models"
	"ipspect/internal/output"
	scantime "ipspect/internal/time"
)

func Run() {
	stages := newStageCounter()

	if models.ActiveEngines.ICMP {
		runTimed("ICMP Discovery", func() {
			runICMP(stages)
		})
	}

	if models.ActiveEngines.ARP {
		runTimed("ARP Discovery", func() {
			runARP(stages)
		})
	}

	if models.ActiveEngines.TCP {
		runTimed("TCP Scanning", func() {
			runTCP(stages)
		})
	}

	output.Log("end", "")
}

func runTimed(
	name string,
	run func(),
) {
	timer := scantime.New(name)
	defer timer.Stop()

	run()
}
