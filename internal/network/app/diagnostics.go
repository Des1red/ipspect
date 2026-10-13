package app

import (
	"fmt"
	"ipspect/internal/output"
	"strings"
	"time"
)

type diagnosticsResult struct {
	requests     int
	unclassified int

	responseRate float64
	coverage     float64

	valid  bool
	status string
}

func calculateDiagnostics(
	stats ProtocolStats,
) diagnosticsResult {
	if stats.Sent < 0 ||
		stats.Retries < 0 ||
		stats.Retries > stats.Sent ||
		stats.Received < 0 ||
		stats.TimedOut < 0 ||
		stats.Dropped < 0 {

		return diagnosticsResult{
			status: "Inconsistent",
		}
	}

	if stats.Sent == 0 {
		if stats.Received != 0 ||
			stats.TimedOut != 0 ||
			stats.Dropped != 0 {

			return diagnosticsResult{
				status: "Inconsistent",
			}
		}

		return diagnosticsResult{
			status: "No data",
		}
	}

	requests := stats.Sent - stats.Retries

	if requests <= 0 {
		return diagnosticsResult{
			status: "Inconsistent",
		}
	}

	classified :=
		stats.Received +
			stats.TimedOut +
			stats.Dropped

	if classified > requests {
		return diagnosticsResult{
			status: "Inconsistent",
		}
	}

	result := diagnosticsResult{
		requests: requests,

		unclassified: requests - classified,

		responseRate: float64(stats.Received) /
			float64(requests) * 100,

		coverage: float64(classified) /
			float64(requests) * 100,

		valid:  true,
		status: "Complete",
	}

	if result.unclassified > 0 {
		result.status = "Partial"
	}

	return result
}

func printDiagnostics() {
	now := time.Now()

	protocols := []Protocol{
		ICMP,
		ARP,
		TCP,
		DNS,
		NetBIOS,
		TCPConnect,
		HTTP,
		HTTPS,
		DNSTCP,
	}

	printed := false

	for _, protocol := range protocols {
		stats, active, _ := snapshotAt(
			protocol,
			now,
		)

		if !active {
			continue
		}

		if !printed {
			output.Log(
				"stage",
				"Network Diagnostics",
			)

			printed = true
		}

		result := calculateDiagnostics(
			stats,
		)

		response := "n/a"
		coverage := "n/a"

		if result.valid {
			response = fmt.Sprintf(
				"%.2f%%",
				result.responseRate,
			)

			coverage = fmt.Sprintf(
				"%.2f%%",
				result.coverage,
			)
		}

		output.Log(
			"text",
			fmt.Sprintf(
				"%-11s  Requests: %-7d Responses: %-7d Response: %-8s Coverage: %-8s Unclassified: %-6d Status: %s",
				strings.ToUpper(string(protocol)),
				result.requests,
				stats.Received,
				response,
				coverage,
				result.unclassified,
				result.status,
			),
		)
	}

	if !printed {
		return
	}

	output.Log("text", "")

	output.Log(
		"text",
		"Response = received / (sent - retries)",
	)

	output.Log(
		"text",
		"Coverage = (received + timed out + dropped) / (sent - retries)",
	)

	output.Log(
		"text",
		"Response rate measures observed replies, not network health",
	)

	output.Log("end", "")
}
