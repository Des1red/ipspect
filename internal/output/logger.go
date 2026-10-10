package output

import (
	"fmt"
	"ipspect/internal/models"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
)

var logMu sync.Mutex

func Log(
	kind string,
	value string,
) {
	logMu.Lock()
	defer logMu.Unlock()

	switch kind {
	case "line":
		fmt.Println(line())

	case "header":
		fmt.Println(header(value))

	case "icmp":
		logICMP()

	case "ports":
		logPorts()

	case "result":
		logResult()
	default:
		fmt.Println(message(kind, value))
	}
}

func logICMP() {
	fmt.Println(
		message(
			"icmp",
			fmt.Sprintf(
				"accept icmp [%s]",
				strings.Join(
					models.LOOT.ICMPReachable,
					", ",
				),
			),
		),
	)
}

func logPorts() {
	explicitPorts := len(models.INFO.Ports) > 0

	for _, host := range models.LOOT.Hosts {
		fmt.Println(
			message("host", host.Target),
		)

		fmt.Println(
			message(
				"open",
				fmt.Sprintf(
					"open     [%s]",
					formatPorts(host.Ports),
				),
			),
		)

		if explicitPorts {
			fmt.Println(
				message(
					"closed",
					fmt.Sprintf(
						"closed   [%s]",
						formatPorts(host.Closed),
					),
				),
			)
		} else {
			fmt.Println(
				message(
					"closed",
					fmt.Sprintf(
						"closed   %d",
						host.ClosedCount,
					),
				),
			)
		}

		fmt.Println(
			message(
				"filtered",
				fmt.Sprintf(
					"filtered %d",
					host.FilteredCount,
				),
			),
		)

		fmt.Println()
	}
}

func logResult() {
	w := tabwriter.NewWriter(
		os.Stdout,
		0,
		4,
		2,
		' ',
		0,
	)

	for _, host := range models.LOOT.Hosts {
		if len(host.Details) == 0 {
			continue
		}

		fmt.Fprintf(
			w,
			"\nHOST\t%s\n",
			host.Target,
		)

		fmt.Fprintln(
			w,
			"PORT\tSTATE\tSERVICE\tBANNER\tLATENCY",
		)

		for _, detail := range host.Details {
			fmt.Fprintf(
				w,
				"%d\t%s\t%s\t%s\t%s\n",
				detail.Port,
				detail.State,
				detail.Service,
				detail.Banner,
				detail.Latency,
			)

			printHeaders(
				w,
				detail.Headers,
			)
		}
	}

	w.Flush()
}
