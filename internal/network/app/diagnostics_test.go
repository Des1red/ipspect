package app

import (
	"math"
	"testing"
)

func TestARPDiagnostics(t *testing.T) {
	stats := ProtocolStats{
		Sent:     751,
		Retries:  498,
		Received: 4,
		TimedOut: 249,
	}

	result := calculateDiagnostics(stats)

	if !result.valid {
		t.Fatal("expected valid diagnostics")
	}

	if result.requests != 253 {
		t.Fatalf(
			"expected 253 requests, got %d",
			result.requests,
		)
	}

	if result.unclassified != 0 {
		t.Fatalf(
			"expected 0 unclassified, got %d",
			result.unclassified,
		)
	}

	if result.coverage != 100 {
		t.Fatalf(
			"expected 100%% coverage, got %.2f%%",
			result.coverage,
		)
	}

	expected := 4.0 / 253.0 * 100

	if math.Abs(result.responseRate-expected) > 0.0001 {
		t.Fatalf(
			"unexpected response rate: %.4f",
			result.responseRate,
		)
	}

	if result.status != "Complete" {
		t.Fatalf(
			"expected Complete, got %s",
			result.status,
		)
	}
}

func TestPartialDiagnostics(t *testing.T) {
	result := calculateDiagnostics(
		ProtocolStats{
			Sent:     4,
			TimedOut: 2,
		},
	)

	if result.status != "Partial" {
		t.Fatalf(
			"expected Partial, got %s",
			result.status,
		)
	}

	if result.coverage != 50 {
		t.Fatalf(
			"expected 50%% coverage, got %.2f%%",
			result.coverage,
		)
	}
}

func TestInconsistentDiagnostics(t *testing.T) {
	result := calculateDiagnostics(
		ProtocolStats{
			Sent:     2,
			Retries:  1,
			Received: 2,
		},
	)

	if result.status != "Inconsistent" {
		t.Fatalf(
			"expected Inconsistent, got %s",
			result.status,
		)
	}
}
