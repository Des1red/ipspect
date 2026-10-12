package app

import (
	"fmt"
	"ipspect/internal/output"
	"strings"
	"time"
)

func Print() {
	now := time.Now()
	printed := false

	for _, protocol := range []Protocol{
		ICMP,
		ARP,
		TCP,
	} {
		stats, active, hasRTT := snapshotAt(
			protocol,
			now,
		)

		if !active {
			continue
		}

		if !printed {
			output.Log(
				"stage",
				"Network Performance",
			)

			printed = true
		}

		minRTT := "n/a"
		avgRTT := "n/a"
		maxRTT := "n/a"

		if hasRTT {
			minRTT = stats.RTT.Minimum.String()
			avgRTT = stats.RTT.Average.String()
			maxRTT = stats.RTT.Maximum.String()
		}

		output.Log(
			"text",
			fmt.Sprintf(
				"%-5s  Sent: %-7d Received: %-7d Dropped: %-6d TimedOut: %-6d RTT: %s / %s / %s  Rate: %.2f pkt/s",
				strings.ToUpper(string(protocol)),
				stats.Sent,
				stats.Received,
				stats.Dropped,
				stats.TimedOut,
				minRTT,
				avgRTT,
				maxRTT,
				stats.TransmissionRate,
			),
		)
	}

	if printed {
		output.Log("end", "")
	}
}
