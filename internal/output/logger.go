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

	case "arp":
		logARP()

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
	logDBLookup()
	logFingerprint()

	fmt.Println()
	fmt.Println(header("Final Result"))

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

			if detail.ServiceReason != "" {
				fmt.Fprintf(
					w,
					"\t\tReason:\t%s\n",
					detail.ServiceReason,
				)
			}

			printHeaders(
				w,
				detail.Headers,
			)
		}
	}

	w.Flush()
}

func logARP() {
	fmt.Println(
		message(
			"arp",
			fmt.Sprintf(
				"accept arp [%s]",
				strings.Join(
					models.LOOT.ARPReachable,
					", ",
				),
			),
		),
	)

	if len(models.LOOT.ARPResults) == 0 {
		return
	}

	w := tabwriter.NewWriter(
		os.Stdout,
		0,
		4,
		2,
		' ',
		0,
	)

	fmt.Fprintln(
		w,
		"IP\tMAC\tVENDOR\tPTR\tNETBIOS\tINTERFACE",
	)

	display := func(value string) string {
		if value == "" {
			return "-"
		}

		return value
	}

	for _, host := range models.LOOT.ARPResults {
		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			host.IP,
			host.MAC,
			display(host.Vendor),
			display(host.PTRName),
			display(host.NetBIOSName),
			host.Interface,
		)
	}

	w.Flush()
}

func logDBLookup() {
	fmt.Println()
	fmt.Println(header("DB Lookup"))

	w := tabwriter.NewWriter(
		os.Stdout,
		0,
		4,
		2,
		' ',
		0,
	)

	fmt.Fprintln(
		w,
		"HOST\tPORT\tIANA SERVICE",
	)

	for _, host := range models.LOOT.Hosts {
		for _, detail := range host.Details {
			if detail.State != "open" {
				continue
			}

			fmt.Fprintf(
				w,
				"%s\t%d\t%s\n",
				host.Target,
				detail.Port,
				detail.DBLookup,
			)
		}
	}

	w.Flush()
}

func logFingerprint() {
	fmt.Println()
	fmt.Println(header("Fingerprint Lookup"))

	w := tabwriter.NewWriter(
		os.Stdout,
		0,
		4,
		2,
		' ',
		0,
	)

	fmt.Fprintln(
		w,
		"HOST\tPORT\tDETECTED\tCONFIDENCE\tPRODUCT\tBANNER\tEVIDENCE",
	)

	display := func(value string) string {
		if value == "" {
			return "-"
		}

		return value
	}

	for _, host := range models.LOOT.Hosts {
		for _, detail := range host.Details {
			if detail.State != "open" {
				continue
			}

			fp := detail.Fingerprint

			if len(fp.Matches) == 0 {
				fmt.Fprintf(
					w,
					"%s\t%d\t-\t-\t-\t-\t%s\n",
					host.Target,
					detail.Port,
					display(fp.Evidence),
				)

				continue
			}

			for _, match := range fp.Matches {
				fmt.Fprintf(
					w,
					"%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
					host.Target,
					detail.Port,
					match.Service,
					fp.Confidence,
					display(match.Product),
					display(match.Banner),
					display(match.Evidence),
				)
			}
		}
	}

	w.Flush()
}
