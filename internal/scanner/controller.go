package scanner

import (
	"ipspect/internal/analyzer"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"ipspect/internal/output"
	scantime "ipspect/internal/time"
)

func Run() {
	if err := analyzer.Load(); err != nil {
		output.Log(
			"error",
			"analyzer initialization failed: "+err.Error(),
		)
		return
	}

	stages := newStageCounter()

	if models.ActiveEngines.ICMP {
		runTimed(
			"ICMP Discovery",
			app.ICMP,
			func() {
				runICMP(stages)
			},
		)
	}

	if models.ActiveEngines.ARP {
		runTimed(
			"ARP Discovery",
			app.ARP,
			func() {
				runARP(stages)
			},
		)
	}

	if models.ActiveEngines.TCP {
		runTimed(
			"TCP Scanning",
			app.TCP,
			func() {
				runTCP(stages)
			},
		)
	}

	output.Log("end", "")
}

func runTimed(
	name string,
	protocol app.Protocol,
	run func(),
) {
	timer := scantime.New(name)

	app.Start(protocol)

	defer func() {
		app.Stop(protocol)
		timer.Stop()
	}()

	run()
}
