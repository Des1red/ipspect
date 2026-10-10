package ping

import (
	"ipspect/internal/models"
	"net"
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
		scanner: scanner,
		total:   len(targets),

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

	state.run()
	state.storeResults()

	return nil
}
