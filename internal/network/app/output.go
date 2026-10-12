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
		DNS,
		NetBIOS,
		TCPConnect,
		HTTP,
		HTTPS,
		DNSTCP,
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

		unit := "pkt/s"

		switch protocol {
		case DNS, TCPConnect, HTTP, HTTPS, DNSTCP:
			unit = "op/s"
		}

		output.Log(
			"text",
			fmt.Sprintf(
				"%-11s  Sent: %-7d Received: %-7d Dropped: %-6d TimedOut: %-6d RTT: %s / %s / %s  Rate: %.2f %s",
				strings.ToUpper(string(protocol)),
				stats.Sent,
				stats.Received,
				stats.Dropped,
				stats.TimedOut,
				minRTT,
				avgRTT,
				maxRTT,
				stats.TransmissionRate,
				unit,
			),
		)
	}

	if printed {
		output.Log("end", "")
	}
}
