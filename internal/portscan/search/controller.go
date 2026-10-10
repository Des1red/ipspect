package search

import (
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
	synprobe "ipspect/internal/portscan/probe"
	"os"
)

func Controller() {
	if err := execute(); err != nil {
		output.Log("error", err.Error())
		os.Exit(1)
	}
}

func execute() error {
	if len(models.INFO.Targets) == 0 {
		return nil
	}

	ports := scanPorts()

	if len(ports) == 0 {
		return nil
	}

	scanner, err := synprobe.NewSYNScanner()
	if err != nil {
		return fmt.Errorf(
			"failed to initialize SYN scanner: %w\n"+
				"ipspect SYN scanning requires raw-socket privileges",
			err,
		)
	}

	defer scanner.Close()

	models.LOOT.Hosts = make(
		[]models.HostResult,
		len(models.INFO.Targets),
	)

	for i, ip := range models.INFO.Targets {
		models.LOOT.Hosts[i].Target =
			ip.String()
	}

	state := &scanState{
		scanner: scanner,
		ports:   ports,

		pending: make(
			map[uint16]*pendingProbe,
		),

		usedPorts: make(
			map[uint16]struct{},
		),

		moreJobs: true,
	}

	return state.run()
}
