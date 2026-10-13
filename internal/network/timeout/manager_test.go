package timeout

import (
	"testing"
	"time"
)

func TestWarmupAndIsolation(t *testing.T) {
	manager := New()

	initial := manager.Duration(
		TCP,
		"192.168.1.1",
	)

	if initial != 7*time.Second {
		t.Fatalf(
			"unexpected initial timeout: %s",
			initial,
		)
	}

	for i := 0; i < 3; i++ {
		manager.Observe(
			TCP,
			"192.168.1.1",
			20*time.Millisecond,
		)
	}

	if got := manager.Duration(
		TCP,
		"192.168.1.1",
	); got != initial {
		t.Fatalf(
			"timeout changed during warmup: %s",
			got,
		)
	}

	manager.Observe(
		TCP,
		"192.168.1.1",
		20*time.Millisecond,
	)

	if got := manager.Duration(
		TCP,
		"192.168.1.1",
	); got != 750*time.Millisecond {
		t.Fatalf(
			"unexpected adaptive timeout: %s",
			got,
		)
	}

	// An unobserved target uses the
	// mode-level estimate as fallback.
	if got := manager.Duration(
		TCP,
		"192.168.1.2",
	); got != 750*time.Millisecond {
		t.Fatalf(
			"mode fallback failed: %s",
			got,
		)
	}

	// ICMP must remain independent.
	if got := manager.Duration(
		ICMP,
		"192.168.1.1",
	); got != 1500*time.Millisecond {
		t.Fatalf(
			"mode isolation failed: %s",
			got,
		)
	}
}

func TestBackoff(t *testing.T) {
	manager := New()

	for i := 0; i < 4; i++ {
		manager.Observe(
			TCP,
			"192.168.1.1",
			20*time.Millisecond,
		)
	}

	expected := []time.Duration{
		750 * time.Millisecond,
		1500 * time.Millisecond,
		3 * time.Second,
		6 * time.Second,
		12 * time.Second,
		12 * time.Second,
	}

	for retry, want := range expected {
		got := manager.Backoff(
			TCP,
			"192.168.1.1",
			retry,
		)

		if got != want {
			t.Fatalf(
				"retry %d: got %s, want %s",
				retry,
				got,
				want,
			)
		}
	}
}

func TestSlowResponses(t *testing.T) {
	manager := New()

	for i := 0; i < 4; i++ {
		manager.Observe(
			TCP,
			"192.168.1.1",
			8*time.Second,
		)
	}

	got := manager.Duration(
		TCP,
		"192.168.1.1",
	)

	if got != 12*time.Second {
		t.Fatalf(
			"unexpected slow-response timeout: %s",
			got,
		)
	}
}

func TestTargetSpecificEstimate(t *testing.T) {
	manager := New()

	for i := 0; i < 4; i++ {
		manager.Observe(
			TCP,
			"router-a",
			20*time.Millisecond,
		)

		manager.Observe(
			TCP,
			"router-b",
			3*time.Second,
		)
	}

	a := manager.Duration(TCP, "router-a")
	b := manager.Duration(TCP, "router-b")

	if a >= b {
		t.Fatalf(
			"target estimates not independent: a=%s b=%s",
			a,
			b,
		)
	}
}
