package app

import "testing"

func TestRetryAccountingAndDiagnostics(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	// One request, retried twice, then timed out.
	Send(ARP)
	Retry(ARP)
	Retry(ARP)
	Timeout(ARP)

	stats := Snapshot().ARP

	if stats.Sent != 3 {
		t.Fatalf("expected 3 transmissions, got %d", stats.Sent)
	}

	if stats.Retries != 2 {
		t.Fatalf("expected 2 retries, got %d", stats.Retries)
	}

	if stats.TimedOut != 1 {
		t.Fatalf("expected 1 timeout, got %d", stats.TimedOut)
	}

	result := calculateDiagnostics(stats)

	if !result.valid {
		t.Fatal("expected valid diagnostics")
	}

	if result.requests != 1 {
		t.Fatalf(
			"expected 1 logical request, got %d",
			result.requests,
		)
	}

	if result.coverage != 100 ||
		result.unclassified != 0 ||
		result.status != "Complete" {
		t.Fatalf(
			"unexpected diagnostics: %+v",
			result,
		)
	}
}
