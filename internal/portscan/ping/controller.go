package ping

import (
	"net"

	"ipspect/internal/models"
	"ipspect/internal/network/timeout"
)

func Controller() error {
	models.LOOT.ICMPReachable = nil

	targets := models.INFO.Targets

	if len(targets) == 0 {
		return nil
	}

	scanner, err := newICMPScanner(targets)
	if err != nil {
		return err
	}

	defer scanner.close()

	state := &scanState{
		scanner:  scanner,
		timeouts: timeout.New(),
		total:    len(targets),

		pending: make(
			map[int]*icmpProbe,
		),

		usedSequences: make(
			map[int]struct{},
		),

		live: make(
			map[string]net.IP,
		),

		nextSequence: 1,
	}

	if err := state.run(); err != nil {
		return err
	}

	state.storeResults()

	return nil
}
