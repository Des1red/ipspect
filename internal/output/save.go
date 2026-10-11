package output

import (
	"fmt"
	"ipspect/internal/models"
	"os"
	"sort"
	"strconv"
	"strings"
)

func Save() (string, error) {
	filename := safeFilename(models.INFO.TargetName) + ".md"

	var b strings.Builder

	b.WriteString("# IPSpect Scan Report\n\n")

	fmt.Fprintf(
		&b,
		"**Target:** %s  \n",
		escapeMarkdown(models.INFO.TargetName),
	)

	writePortSelection(&b)
	writeICMPResults(&b)
	writeARPResults(&b)
	writeTCPResults(&b)
	writeIdentificationResults(&b)
	writeFinalResults(&b)

	if err := os.WriteFile(
		filename,
		[]byte(b.String()),
		0644,
	); err != nil {
		return "", err
	}

	return filename, nil
}

func writePortSelection(
	b *strings.Builder,
) {
	portSpec := strings.TrimSpace(
		models.INFO.PortSpec,
	)

	if portSpec == "" {
		portSpec = fmt.Sprintf(
			"%d-%d",
			models.INFO.PortStart,
			models.INFO.PortEnd,
		)
	}

	fmt.Fprintf(
		b,
		"**Ports:** %s\n\n",
		escapeMarkdown(portSpec),
	)
}

func writeICMPResults(
	b *strings.Builder,
) {
	b.WriteString(
		"## 01 / 05 — ICMP Discovery\n\n",
	)

	if len(models.LOOT.ICMPReachable) == 0 {
		b.WriteString(
			"No targets responded to ICMP echo.\n\n",
		)
		return
	}

	for _, ip := range models.LOOT.ICMPReachable {
		fmt.Fprintf(
			b,
			"- %s\n",
			escapeMarkdown(ip),
		)
	}

	b.WriteString("\n")
}

func writeARPResults(
	b *strings.Builder,
) {
	b.WriteString(
		"## 02 / 05 — ARP Discovery\n\n",
	)

	if len(models.LOOT.ARPResults) == 0 {
		b.WriteString(
			"No ARP responses recorded.\n\n",
		)
		return
	}

	rows := make(
		[][]string,
		0,
		len(models.LOOT.ARPResults),
	)

	for _, host := range models.LOOT.ARPResults {
		rows = append(
			rows,
			[]string{
				host.IP,
				host.MAC,
				host.Vendor,
				host.PTRName,
				host.NetBIOSName,
				host.Interface,
			},
		)
	}

	writeMarkdownTable(
		b,
		[]string{
			"IP",
			"MAC",
			"Vendor",
			"PTR",
			"NetBIOS",
			"Interface",
		},
		rows,
	)
}

func writeTCPResults(
	b *strings.Builder,
) {
	b.WriteString(
		"## 03 / 05 — TCP SYN Scanning\n\n",
	)

	if len(models.LOOT.Hosts) == 0 {
		b.WriteString(
			"No TCP scan results recorded.\n\n",
		)
		return
	}

	explicitPorts := len(models.INFO.Ports) > 0

	rows := make(
		[][]string,
		0,
		len(models.LOOT.Hosts),
	)

	for _, host := range models.LOOT.Hosts {
		closed := strconv.Itoa(
			host.ClosedCount,
		)

		if explicitPorts {
			closed = "[" +
				formatPorts(host.Closed) +
				"]"
		}

		rows = append(
			rows,
			[]string{
				host.Target,
				"[" + formatPorts(host.Ports) + "]",
				closed,
				strconv.Itoa(host.FilteredCount),
			},
		)
	}

	writeMarkdownTable(
		b,
		[]string{
			"Host",
			"Open",
			"Closed",
			"Filtered",
		},
		rows,
	)
}

func writeIdentificationResults(
	b *strings.Builder,
) {
	b.WriteString(
		"## 04 / 05 — Service Identification\n\n",
	)

	var dbRows [][]string
	var fpRows [][]string

	for _, host := range models.LOOT.Hosts {
		for _, detail := range host.Details {
			if detail.State != "open" {
				continue
			}

			port := strconv.Itoa(
				detail.Port,
			)

			dbRows = append(
				dbRows,
				[]string{
					host.Target,
					port,
					detail.DBLookup,
				},
			)

			fp := detail.Fingerprint

			if len(fp.Matches) == 0 {
				fpRows = append(
					fpRows,
					[]string{
						host.Target,
						port,
						"",
						"",
						"",
						"",
						fp.Evidence,
					},
				)

				continue
			}

			for _, match := range fp.Matches {
				fpRows = append(
					fpRows,
					[]string{
						host.Target,
						port,
						match.Service,
						fp.Confidence,
						match.Product,
						match.Banner,
						match.Evidence,
					},
				)
			}
		}
	}

	b.WriteString(
		"### DB Lookup (IANA)\n\n",
	)

	if len(dbRows) == 0 {
		b.WriteString(
			"No open ports available for database lookup.\n\n",
		)
	} else {
		writeMarkdownTable(
			b,
			[]string{
				"Host",
				"Port",
				"IANA Service",
			},
			dbRows,
		)
	}

	b.WriteString(
		"### Fingerprint Lookup\n\n",
	)

	if len(fpRows) == 0 {
		b.WriteString(
			"No open ports available for fingerprinting.\n\n",
		)
	} else {
		writeMarkdownTable(
			b,
			[]string{
				"Host",
				"Port",
				"Detected",
				"Confidence",
				"Product",
				"Banner",
				"Evidence",
			},
			fpRows,
		)
	}
}

func writeFinalResults(
	b *strings.Builder,
) {
	b.WriteString(
		"## 05 / 05 — Scan Results\n\n",
	)

	any := false

	for _, host := range models.LOOT.Hosts {
		if len(host.Details) == 0 {
			continue
		}

		any = true

		fmt.Fprintf(
			b,
			"### Host %s\n\n",
			escapeMarkdown(host.Target),
		)

		rows := make(
			[][]string,
			0,
			len(host.Details),
		)

		for _, detail := range host.Details {
			rows = append(
				rows,
				[]string{
					strconv.Itoa(detail.Port),
					detail.State,
					detail.Service,
					detail.Latency.String(),
				},
			)
		}

		writeMarkdownTable(
			b,
			[]string{
				"Port",
				"State",
				"Service",
				"Connect Latency",
			},
			rows,
		)

		for _, detail := range host.Details {
			if detail.Banner == "" &&
				detail.ServiceReason == "" &&
				len(detail.Headers) == 0 &&
				len(detail.Fingerprint.Matches) < 2 {
				continue
			}

			fmt.Fprintf(
				b,
				"#### Port %d — Details\n\n",
				detail.Port,
			)

			if detail.Banner != "" {
				fmt.Fprintf(
					b,
					"**Banner:** %s  \n",
					escapeMarkdown(detail.Banner),
				)
			}

			if detail.ServiceReason != "" {
				fmt.Fprintf(
					b,
					"**Reason:** %s  \n",
					escapeMarkdown(detail.ServiceReason),
				)
			}

			b.WriteString("\n")

			if len(detail.Fingerprint.Matches) > 1 {
				b.WriteString(
					"**Confirmed protocol observations:**\n\n",
				)

				for _, match := range detail.Fingerprint.Matches {
					fmt.Fprintf(
						b,
						"##### %s\n\n",
						escapeMarkdown(match.Service),
					)

					if match.Product != "" {
						fmt.Fprintf(
							b,
							"**Product:** %s  \n",
							escapeMarkdown(match.Product),
						)
					}

					if match.Banner != "" {
						fmt.Fprintf(
							b,
							"**Banner:** %s  \n",
							escapeMarkdown(match.Banner),
						)
					}

					if match.Evidence != "" {
						fmt.Fprintf(
							b,
							"**Evidence:** %s  \n",
							escapeMarkdown(match.Evidence),
						)
					}

					b.WriteString("\n")

					writeDetailHeaders(
						b,
						match.Headers,
					)
				}
			} else {
				headers := detail.Headers

				if len(headers) == 0 &&
					len(detail.Fingerprint.Matches) == 1 {

					headers = detail.Fingerprint.Matches[0].Headers
				}

				writeDetailHeaders(
					b,
					headers,
				)
			}
		}
	}

	if !any {
		b.WriteString(
			"No port details recorded.\n\n",
		)
	}
}

func writeDetailHeaders(
	b *strings.Builder,
	headers map[string][]string,
) {
	if len(headers) == 0 {
		return
	}

	b.WriteString(
		"**HTTP Headers:**\n\n",
	)

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
		for _, value := range headers[key] {
			if sensitiveHeader(key) {
				value = "[redacted]"
			}

			fmt.Fprintf(
				b,
				"- **%s:** %s\n",
				escapeMarkdown(key),
				escapeMarkdown(value),
			)
		}
	}

	b.WriteString("\n")
}

func sensitiveHeader(
	name string,
) bool {
	switch strings.ToLower(
		strings.TrimSpace(name),
	) {
	case "set-cookie",
		"cookie",
		"authorization",
		"proxy-authorization",
		"www-authenticate",
		"proxy-authenticate":

		return true
	}

	return false
}

func writeMarkdownTable(
	b *strings.Builder,
	columns []string,
	rows [][]string,
) {
	b.WriteString("| ")
	b.WriteString(
		strings.Join(columns, " | "),
	)

	b.WriteString(" |\n|")

	for range columns {
		b.WriteString(" --- |")
	}

	b.WriteString("\n")

	for _, row := range rows {
		b.WriteString("| ")

		for i := range columns {
			if i > 0 {
				b.WriteString(" | ")
			}

			value := ""

			if i < len(row) {
				value = row[i]
			}

			b.WriteString(
				markdownValue(value),
			)
		}

		b.WriteString(" |\n")
	}

	b.WriteString("\n")
}

func markdownValue(
	value string,
) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}

	return escapeMarkdown(value)
}

func escapeMarkdown(
	value string,
) string {
	value = strings.ReplaceAll(
		value,
		"\r",
		"",
	)

	value = strings.ReplaceAll(
		value,
		"\n",
		" ",
	)

	value = strings.ReplaceAll(
		value,
		"&",
		"&amp;",
	)

	value = strings.ReplaceAll(
		value,
		"<",
		"&lt;",
	)

	value = strings.ReplaceAll(
		value,
		">",
		"&gt;",
	)

	value = strings.ReplaceAll(
		value,
		"\\",
		"\\\\",
	)

	value = strings.ReplaceAll(
		value,
		"|",
		"\\|",
	)

	value = strings.ReplaceAll(
		value,
		"`",
		"\\`",
	)

	value = strings.ReplaceAll(
		value,
		"*",
		"\\*",
	)

	value = strings.ReplaceAll(
		value,
		"_",
		"\\_",
	)

	return value
}

func safeFilename(
	value string,
) string {
	value = strings.TrimSpace(value)

	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"*", "-",
		"?", "-",
		"\"", "-",
		"<", "-",
		">", "-",
		"|", "-",
	)

	value = replacer.Replace(value)

	if value == "" ||
		value == "." ||
		value == ".." {
		return "ipspect-results"
	}

	return value
}
