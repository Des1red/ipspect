package output

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

const (
	reset = "\033[0m"
	bold  = "\033[1m"

	orange = "\033[38;5;208m"
	gray   = "\033[90m"
	cyan   = "\033[36m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
)

func line() string {
	return bold +
		strings.Repeat(
			orange+"===="+gray+"====",
			5,
		) +
		reset
}

func header(value string) string {
	return bold +
		cyan +
		value +
		reset
}

func message(
	kind string,
	value string,
) string {
	switch kind {
	case "icmp", "arp", "open", "success":
		return green + value + reset

	case "closed":
		return gray + value + reset

	case "filtered", "warning":
		return yellow + value + reset

	case "error":
		return red + value + reset

	case "host":
		return bold + orange + value + reset

	default:
		return value
	}
}

func formatPorts(
	ports []int,
) string {
	values := make(
		[]string,
		len(ports),
	)

	for i, port := range ports {
		values[i] = strconv.Itoa(port)
	}

	return strings.Join(
		values,
		", ",
	)
}

func printHeaders(
	w *tabwriter.Writer,
	headers map[string][]string,
) {
	if len(headers) == 0 {
		return
	}

	keys := make(
		[]string,
		0,
		len(headers),
	)

	for key := range headers {
		keys = append(
			keys,
			key,
		)
	}

	sort.Strings(keys)

	for _, key := range keys {
		fmt.Fprintf(
			w,
			"\t\t%s\t%s\n",
			key+":",
			strings.Join(
				headers[key],
				", ",
			),
		)
	}
}
