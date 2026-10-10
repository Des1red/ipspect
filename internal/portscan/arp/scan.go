package arp

import (
	"fmt"
	"time"
)

func scanInterface(
	group interfaceGroup,
) ([]arpHost, error) {
	scanner, err := openScanner(group)

	if err != nil {
		return nil, err
	}

	ticker := time.NewTicker(
		time.Second / arpPacketsPerSecond,
	)

	defer ticker.Stop()

	for _, ip := range group.targets {
		<-ticker.C

		if err := scanner.send(ip); err != nil {
			scanner.close()

			return scanner.results(),
				fmt.Errorf(
					"send ARP to %s: %w",
					ip,
					err,
				)
		}
	}

	time.Sleep(
		arpReplyWait,
	)

	scanner.close()

	return scanner.results(), nil
}
