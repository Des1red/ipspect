package ping

import (
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"ipspect/internal/network/app"
	"ipspect/internal/network/timeout"
)

func testICMPState(t *testing.T) *scanState {
	t.Helper()

	app.Reset()
	t.Cleanup(app.Reset)

	ip := net.IPv4(192, 0, 2, 10)
	now := time.Now()

	return &scanState{
		timeouts: timeout.New(),

		pending: map[int]*icmpProbe{
			7: {
				ip:       ip,
				seq:      7,
				attempts: 1,
				sentAt:   now.Add(-2 * time.Second),
				deadline: now.Add(-time.Millisecond),
			},
		},

		usedSequences: map[int]struct{}{
			7: {},
		},

		live: make(map[string]net.IP),
	}
}

func TestICMPRetrySendFailure(t *testing.T) {
	s := testICMPState(t)
	pending := s.pending[7]

	app.Send(app.ICMP)

	calls := 0

	s.retrySend = func(p *icmpProbe) error {
		calls++

		if calls == 1 {
			return fmt.Errorf(
				"send: %w",
				syscall.ENOBUFS,
			)
		}

		app.Retry(app.ICMP)
		return nil
	}

	oldDeadline := pending.deadline
	now := time.Now()

	retried, err := s.retryDue(now)
	if err != nil || !retried {
		t.Fatalf(
			"expected recoverable failure: retried=%v err=%v",
			retried,
			err,
		)
	}

	if pending.attempts != 1 {
		t.Fatalf(
			"failed send consumed retry: attempts=%d",
			pending.attempts,
		)
	}

	if !pending.deadline.Equal(oldDeadline) {
		t.Fatal("failed send changed deadline")
	}

	if !s.pauseUntil.After(now) {
		t.Fatal("congestion pause not scheduled")
	}

	stats := app.Snapshot().ICMP

	if stats.Sent != 1 || stats.Retries != 0 {
		t.Fatalf("failed send counted: %+v", stats)
	}

	// Directly test the next eligible send.
	// The real scheduler respects pauseUntil.
	retried, err = s.retryDue(time.Now())
	if err != nil || !retried {
		t.Fatalf(
			"expected successful retry: retried=%v err=%v",
			retried,
			err,
		)
	}

	if pending.attempts != 2 {
		t.Fatalf(
			"expected second attempt, got %d",
			pending.attempts,
		)
	}

	if !pending.deadline.After(time.Now()) {
		t.Fatal("successful retry has expired deadline")
	}

	stats = app.Snapshot().ICMP

	if stats.Sent != 2 ||
		stats.Retries != 1 ||
		stats.TimedOut != 0 {
		t.Fatalf("incorrect retry accounting: %+v", stats)
	}
}

func TestICMPLateReplyAcceptedOnce(t *testing.T) {
	s := testICMPState(t)
	pending := s.pending[7]

	// Simulate an unanswered initial request
	// followed by a successful retransmission.
	pending.attempts = 2
	pending.sentAt = time.Now().Add(-time.Second)

	app.Send(app.ICMP)
	app.Retry(app.ICMP)

	reply := icmpReply{
		ip:         pending.ip,
		seq:        pending.seq,
		receivedAt: time.Now(),
	}

	s.handleReply(reply)
	s.handleReply(reply)

	stats := app.Snapshot().ICMP

	if stats.Received != 1 {
		t.Fatalf(
			"duplicate reply counted: received=%d",
			stats.Received,
		)
	}

	if len(s.pending) != 0 ||
		len(s.usedSequences) != 0 ||
		len(s.live) != 1 {
		t.Fatal("successful reply did not release probe")
	}

	// RTT following a retransmission is ambiguous.
	if stats.RTT != (app.RTTStats{}) {
		t.Fatal("ambiguous RTT entered statistics")
	}
}

func TestICMPFinalTimeoutOnlyOnce(t *testing.T) {
	s := testICMPState(t)
	pending := s.pending[7]

	pending.attempts = icmpRetries + 1

	app.Send(app.ICMP)

	for i := 0; i < icmpRetries; i++ {
		app.Retry(app.ICMP)
	}

	s.expireProbes(time.Now())
	s.expireProbes(time.Now())

	stats := app.Snapshot().ICMP

	if stats.TimedOut != 1 {
		t.Fatalf(
			"expected one final timeout, got %d",
			stats.TimedOut,
		)
	}

	if stats.Sent-stats.Retries !=
		stats.Received+stats.TimedOut+stats.Dropped {
		t.Fatalf("inconsistent accounting: %+v", stats)
	}

	if len(s.pending) != 0 ||
		len(s.usedSequences) != 0 {
		t.Fatal("timed-out probe was not released")
	}
}
