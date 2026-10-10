package arp

import (
	"fmt"
	"ipspect/internal/models"
)

func Controller() error {
	models.LOOT.ARPReachable = nil
	models.LOOT.ARPResults = nil

	if len(models.INFO.Targets) == 0 {
		return nil
	}

	groups, err := localInterfaces(
		models.INFO.Targets,
	)

	if err != nil {
		return err
	}

	found := make(
		map[string]arpHost,
	)

	var firstErr error

	for _, group := range groups {
		addresses, err := scanInterface(
			group,
		)

		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf(
				"ARP on %s: %w",
				group.iface.Name,
				err,
			)
		}

		for _, host := range addresses {
			found[host.ip.String()] = host
		}
	}

	storeResults(found)

	return firstErr
}
