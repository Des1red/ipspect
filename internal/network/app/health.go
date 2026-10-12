package app

import (
	"fmt"
	"ipspect/internal/output"
	"strings"
	"time"
)

const (
	minHealthCoverage = 80.0
	minHealthSamples  = 10
)

type healthResult struct {
	score        float64
	coverage     float64
	unclassified int

	hasScore  bool
	qualified bool
	status    string
}

func calculateHealth(
	stats ProtocolStats,
) healthResult {
	if stats.Sent < 0 ||
		stats.Received < 0 ||
		stats.TimedOut < 0 ||
		stats.Dropped < 0 {

		return healthResult{
			status: "Inconsistent",
		}
	}

	classified :=
		stats.Received +
			stats.TimedOut +
			stats.Dropped

	if classified > stats.Sent {
		return healthResult{
			status: "Inconsistent",
		}
	}

	if stats.Sent == 0 {
		return healthResult{
			status: "No data",
		}
	}

	result := healthResult{
		unclassified: stats.Sent - classified,

		coverage: float64(classified) /
			float64(stats.Sent) * 100,
	}

	if classified == 0 {
		result.status = "Inconclusive"
		return result
	}

	result.score =
		float64(stats.Received) /
			float64(classified) * 100

	result.hasScore = true

	if result.coverage < minHealthCoverage {
		result.status = "Inconclusive"
		return result
	}

	if classified < minHealthSamples {
		result.status = "Limited"
		return result
	}

	result.qualified = true
	result.status = healthStatus(result.score)

	return result
}

func healthStatus(
	score float64,
) string {
	switch {
	case score >= 98:
		return "Healthy"

	case score >= 90:
		return "Watch"

	default:
		return "Degraded"
	}
}

func printHealth() {
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

	activeCount := 0
	qualifiedCount := 0
	totalScore := 0.0

	for _, protocol := range protocols {
		stats, active, _ := snapshotAt(
			protocol,
			now,
		)

		if !active {
			continue
		}

		if activeCount == 0 {
			output.Log(
				"stage",
				"Network Health",
			)
		}

		activeCount++

		health := calculateHealth(stats)

		score := "n/a"
		coverage := "n/a"

		if health.hasScore {
			score = fmt.Sprintf(
				"%.2f%%",
				health.score,
			)
		}

		if stats.Sent > 0 &&
			health.status != "Inconsistent" {

			coverage = fmt.Sprintf(
				"%.2f%%",
				health.coverage,
			)
		}

		output.Log(
			"text",
			fmt.Sprintf(
				"%-11s  Health: %-8s Coverage: %-8s Unclassified: %-6d Status: %s",
				strings.ToUpper(string(protocol)),
				score,
				coverage,
				health.unclassified,
				health.status,
			),
		)

		if health.qualified {
			totalScore += health.score
			qualifiedCount++
		}
	}

	if activeCount == 0 {
		return
	}

	output.Log("text", "")

	if qualifiedCount == 0 {
		output.Log(
			"text",
			"Overall: Inconclusive — insufficient classified observations",
		)
	} else {
		overall := totalScore /
			float64(qualifiedCount)

		output.Log(
			"text",
			fmt.Sprintf(
				"Overall: %.2f%% (%s) — %d/%d categories qualified",
				overall,
				healthStatus(overall),
				qualifiedCount,
				activeCount,
			),
		)
	}

	output.Log(
		"text",
		"Health = received / classified outcomes; Coverage = classified / sent",
	)

	output.Log("end", "")
}
