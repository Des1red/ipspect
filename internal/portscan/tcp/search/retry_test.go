package search

import (
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"ipspect/internal/network/timeout"
	synprobe "ipspect/internal/portscan/tcp/probe"
)

func testTCPState(t *testing.T) *scanState {
	t.Helper()

	app.Reset()
	t.Cleanup(app.Reset)

	ip := net.IPv4(192, 0, 2, 20)
	now := time.Now()

	pending := &pendingProbe{
		job: scanJob{
			hostIndex: 0,
			ip:        ip,
			port:      22,
		},

		srcIP:   net.IPv4(192, 0, 2, 1),
		srcPort: 50100,
		seq:     123456,

		attempts: 1,
		sentAt:   now.Add(-2 * time.Second),
		deadline: now.Add(-time.Millisecond),
	}

	return &scanState{
		timeouts: timeout.New(),

		pending: map[uint16]*pendingProbe{
			pending.srcPort: pending,
		},

		usedPorts: map[uint16]struct{}{
			pending.srcPort: {},
		},
	}
}

func testTCPHost(t *testing.T) {
	t.Helper()

	previous := models.LOOT

	t.Cleanup(func() {
		models.LOOT = previous
	})

	models.LOOT.Hosts = []models.HostResult{
		{
			Target: "192.0.2.20",
		},
	}
}

func TestTCPRetrySendFailure(t *testing.T) {
	s := testTCPState(t)
	pending := s.pending[50100]

	app.Send(app.TCP)

	calls := 0

	s.retrySend = func(p *pendingProbe) error {
		calls++

		if calls == 1 {
			return fmt.Errorf(
				"send: %w",
				syscall.ENOBUFS,
			)
		}

		app.Retry(app.TCP)
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
		t.Fatal("failed SYN consumed retry allowance")
	}

	if !pending.deadline.Equal(oldDeadline) {
		t.Fatal("failed SYN changed deadline")
	}

	if !s.pauseUntil.After(now) {
		t.Fatal("TCP congestion pause not scheduled")
	}

	stats := app.Snapshot().TCP

	if stats.Sent != 1 || stats.Retries != 0 {
		t.Fatalf("failed SYN counted: %+v", stats)
	}

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
			"expected two attempts, got %d",
			pending.attempts,
		)
	}

	if !pending.deadline.After(time.Now()) {
		t.Fatal("successful retry has expired deadline")
	}

	stats = app.Snapshot().TCP

	if stats.Sent != 2 ||
		stats.Retries != 1 ||
		stats.TimedOut != 0 {
		t.Fatalf("incorrect retry accounting: %+v", stats)
	}
}

func TestTCPLateRSTAcceptedOnce(t *testing.T) {
	s := testTCPState(t)
	testTCPHost(t)

	pending := s.pending[50100]
	pending.attempts = 2

	app.Send(app.TCP)
	app.Retry(app.TCP)

	reply := synprobe.Reply{
		SrcIP:      pending.job.ip,
		SrcPort:    uint16(pending.job.port),
		DstPort:    pending.srcPort,
		Ack:        pending.seq + 1,
		Flags:      synprobe.FlagRST | synprobe.FlagACK,
		ReceivedAt: time.Now(),
	}

	// An incorrect acknowledgement must not
	// release or classify the pending probe.
	wrong := reply
	wrong.Ack++

	s.handleReply(wrong)

	if len(s.pending) != 1 {
		t.Fatal("incorrect ACK released probe")
	}

	s.handleReply(reply)
	s.handleReply(reply)

	if models.LOOT.Hosts[0].ClosedCount != 1 {
		t.Fatalf(
			"expected one closed port, got %d",
			models.LOOT.Hosts[0].ClosedCount,
		)
	}

	stats := app.Snapshot().TCP

	if stats.Received != 1 || stats.TimedOut != 0 {
		t.Fatalf("incorrect response accounting: %+v", stats)
	}

	if len(s.pending) != 0 ||
		len(s.usedPorts) != 0 {
		t.Fatal("successful TCP reply did not release probe")
	}

	if stats.RTT != (app.RTTStats{}) {
		t.Fatal("ambiguous retransmission RTT was recorded")
	}
}

func TestTCPFinalTimeoutFilteredOnce(t *testing.T) {
	s := testTCPState(t)
	testTCPHost(t)

	s.pending[50100].attempts = synRetries + 1

	app.Send(app.TCP)

	for i := 0; i < synRetries; i++ {
		app.Retry(app.TCP)
	}

	s.expireProbes(time.Now())
	s.expireProbes(time.Now())

	if models.LOOT.Hosts[0].FilteredCount != 1 {
		t.Fatalf(
			"expected one filtered port, got %d",
			models.LOOT.Hosts[0].FilteredCount,
		)
	}

	stats := app.Snapshot().TCP

	if stats.TimedOut != 1 ||
		stats.Sent-stats.Retries !=
			stats.Received+stats.TimedOut+stats.Dropped {
		t.Fatalf("inconsistent final outcome: %+v", stats)
	}

	if len(s.pending) != 0 ||
		len(s.usedPorts) != 0 {
		t.Fatal("filtered TCP probe was not released")
	}
}
