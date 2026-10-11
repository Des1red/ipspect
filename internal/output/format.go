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

const minStageWidth = 42

func stageWidth(
	value string,
) int {
	width := len([]rune(value)) + 2

	if width < minStageWidth {
		width = minStageWidth
	}

	return width
}

func stage(
	value string,
) string {
	width := stageWidth(value)

	border := strings.Repeat(
		"─",
		width,
	)

	padding := strings.Repeat(
		" ",
		width-len([]rune(value))-2,
	)

	return orange +
		"┌" + border + "┐" +
		reset + "\n" +
		orange + "│" + reset +
		" " + bold + cyan + value + reset +
		padding + " " +
		orange + "│" + reset + "\n" +
		orange + "├" + border + "┘" +
		reset
}

func writeTable(
	build func(*tabwriter.Writer),
) {
	var buffer strings.Builder

	w := tabwriter.NewWriter(
		&buffer,
		0,
		4,
		2,
		' ',
		0,
	)

	build(w)

	if err := w.Flush(); err != nil {
		fmt.Fprintln(
			stageOutput,
			message("error", err.Error()),
		)
		return
	}

	title, content, found := strings.Cut(
		buffer.String(),
		"\n",
	)

	if title == "" {
		return
	}

	fmt.Fprintln(
		stageOutput,
		bold+yellow+title+reset,
	)

	if found && content != "" {
		fmt.Fprint(
			stageOutput,
			content,
		)
	}
}

func writeResultField(
	label string,
	value string,
) {
	const maxWidth = 96

	prefix := "  " + label + ": "
	indent := strings.Repeat(
		" ",
		len([]rune(prefix)),
	)

	current := prefix
	currentWidth := len([]rune(prefix))
	prefixWidth := currentWidth

	for _, word := range strings.Fields(value) {
		wordWidth := len([]rune(word))

		if currentWidth > prefixWidth &&
			currentWidth+1+wordWidth > maxWidth {

			fmt.Fprintln(
				stageOutput,
				current,
			)

			current = indent + word
			currentWidth = prefixWidth + wordWidth

			continue
		}

		if currentWidth > prefixWidth {
			current += " "
			currentWidth++
		}

		current += word
		currentWidth += wordWidth
	}

	fmt.Fprintln(
		stageOutput,
		current,
	)
}

func printResultHeaders(
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
		writeResultField(
			"  "+key,
			strings.Join(
				headers[key],
				", ",
			),
		)
	}
}
