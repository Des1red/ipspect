package output

import (
	"fmt"
	"ipspect/internal/models"
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
	case "stage":
		beginStage(value)

	case "end":
		finishStage()

	case "line":
		fmt.Fprintln(
			stageOutput,
			line(),
		)

	case "header":
		fmt.Fprintln(
			stageOutput,
			header(value),
		)

	case "icmp":
		logICMP()

	case "arp":
		logARP()

	case "ports":
		logPorts()

	case "identification":
		logIdentification()

	case "result":
		logResult()

	case "debug":
		logDebug(value)
	default:
		fmt.Fprintln(
			stageOutput,
			message(kind, value),
		)
	}
}

func logIdentification() {
	logDBLookup()
	logFingerprint()
}

func logICMP() {
	fmt.Fprintln(
		stageOutput,
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

	for i, host := range models.LOOT.Hosts {
		if i > 0 {
			fmt.Fprintln(stageOutput)
		}
		fmt.Fprintln(
			stageOutput,
			message(
				"host",
				host.Target,
			),
		)

		fmt.Fprintln(
			stageOutput,
			message(
				"open",
				fmt.Sprintf(
					"open     [%s]",
					formatPorts(host.Ports),
				),
			),
		)

		if explicitPorts {
			fmt.Fprintln(
				stageOutput,
				message(
					"closed",
					fmt.Sprintf(
						"closed   [%s]",
						formatPorts(host.Closed),
					),
				),
			)
		} else {
			fmt.Fprintln(
				stageOutput,
				message(
					"closed",
					fmt.Sprintf(
						"closed   %d",
						host.ClosedCount,
					),
				),
			)
		}

		fmt.Fprintln(
			stageOutput,
			message(
				"filtered",
				fmt.Sprintf(
					"filtered %d",
					host.FilteredCount,
				),
			),
		)
	}
}

func logResult() {
	for _, host := range models.LOOT.Hosts {
		if len(host.Details) == 0 {
			continue
		}

		fmt.Fprintln(
			stageOutput,
			message(
				"host",
				"HOST  "+host.Target,
			),
		)

		// Compact port summary.
		writeTable(func(w *tabwriter.Writer) {
			fmt.Fprintln(
				w,
				"PORT\tSTATE\tSERVICE\tLATENCY",
			)

			for _, detail := range host.Details {
				fmt.Fprintf(
					w,
					"%d\t%s\t%s\t%s\n",
					detail.Port,
					detail.State,
					detail.Service,
					detail.Latency,
				)
			}
		})

		// Separate detailed information.
		for _, detail := range host.Details {
			if detail.Banner == "" &&
				detail.ServiceReason == "" &&
				len(detail.Headers) == 0 {
				continue
			}

			fmt.Fprintln(stageOutput)

			fmt.Fprintln(
				stageOutput,
				header(
					fmt.Sprintf(
						"Port %d — Details",
						detail.Port,
					),
				),
			)

			if detail.Banner != "" {
				writeResultField(
					"Banner",
					detail.Banner,
				)
			}

			if detail.ServiceReason != "" {
				writeResultField(
					"Reason",
					detail.ServiceReason,
				)
			}

			if len(detail.Headers) > 0 {
				fmt.Fprintln(
					stageOutput,
					"  Headers:",
				)

				printResultHeaders(
					detail.Headers,
				)
			}
		}

		fmt.Fprintln(stageOutput)
	}
}

func logARP() {
	fmt.Fprintln(
		stageOutput,
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

	writeTable(func(w *tabwriter.Writer) {
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
	})
}

func logDBLookup() {
	fmt.Fprintln(stageOutput)

	fmt.Fprintln(
		stageOutput,
		header("DB Lookup"),
	)

	writeTable(func(w *tabwriter.Writer) {
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
	})
}

func logFingerprint() {
	fmt.Fprintln(stageOutput)

	fmt.Fprintln(
		stageOutput,
		header("Fingerprint Lookup"),
	)

	writeTable(func(w *tabwriter.Writer) {
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
	})
}

func logDebug(value string) {
	if !models.DEBUG {
		return
	}

	fmt.Fprintln(
		stageOutput,
		"[DEBUG]\t"+value,
	)
}
