package arp

import (
	"fmt"
	"net"
	"time"
)

func scanInterface(
	group interfaceGroup,
) ([]arpHost, error) {
	scanner, err := openScanner(group)

	if err != nil {
		return nil, err
	}

	sendTicker := time.NewTicker(
		time.Second / arpPacketsPerSecond,
	)

	defer sendTicker.Stop()

	expireTicker := time.NewTicker(
		25 * time.Millisecond,
	)

	defer expireTicker.Stop()

	var retryQueue []net.IP

	next := 0

	for next < len(group.targets) ||
		scanner.hasPending() ||
		len(retryQueue) > 0 {

		select {
		case <-expireTicker.C:
			retryQueue = append(
				retryQueue,
				scanner.expireProbes(
					time.Now(),
				)...,
			)

		case <-sendTicker.C:
			var target net.IP
			var retry bool

			if len(retryQueue) > 0 {
				target = retryQueue[0]

				retryQueue[0] = nil

				retryQueue = retryQueue[1:]

				retry = true

			} else if next < len(group.targets) {
				target = group.targets[next]

				next++

			} else {
				continue
			}

			if retry {
				err = scanner.retry(
					target,
				)
			} else {
				err = scanner.send(
					target,
				)
			}

			if err != nil {
				scanner.close()

				return scanner.results(),
					fmt.Errorf(
						"send ARP to %s: %w",
						target,
						err,
					)
			}
		}
	}

	scanner.close()

	scanner.recordTimeouts()

	return scanner.results(), nil
}
