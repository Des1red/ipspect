//go:build linux

package arp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"ipspect/internal/network/app"
	"ipspect/internal/network/timeout"
)

func TestARPExpiryAndRetryQueue(t *testing.T) {
	app.Reset()
	t.Cleanup(app.Reset)

	now := time.Now()
	ip := net.IPv4(192, 0, 2, 10)
	key := ip.String()

	pending := &pendingARP{
		sentAt:   now.Add(-time.Second),
		deadline: now.Add(-time.Millisecond),
	}

	s := &scanner{
		expected: map[string]*pendingARP{
			key: pending,
		},
		found: make(map[string]arpHost),
	}

	app.Send(app.ARP)

	for attempt := 0; attempt < arpRetries; attempt++ {
		retries := s.expireProbes(now)

		if len(retries) != 1 ||
			!retries[0].Equal(ip) {
			t.Fatalf(
				"attempt %d: expected one retry",
				attempt,
			)
		}

		// The queued flag prevents the same
		// expired request from being queued twice.
		if extra := s.expireProbes(now); len(extra) != 0 {
			t.Fatal("duplicate retry queued")
		}

		pending.retries = attempt + 1
		pending.queued = false
		pending.deadline = now.Add(-time.Millisecond)

		app.Retry(app.ARP)
	}

	// All permitted retries have been used.
	if retries := s.expireProbes(now); len(retries) != 0 {
		t.Fatal("retry queued after exhaustion")
	}

	if len(s.expected) != 0 || s.missed != 1 {
		t.Fatalf(
			"expected one final miss, got missed=%d pending=%d",
			s.missed,
			len(s.expected),
		)
	}

	s.recordTimeouts()

	stats := app.Snapshot().ARP

	if stats.Sent != 1+arpRetries ||
		stats.Retries != arpRetries ||
		stats.TimedOut != 1 {
		t.Fatalf("incorrect ARP accounting: %+v", stats)
	}
}

func TestARPLateReplyAcceptedOnce(t *testing.T) {
	app.Reset()
	t.Cleanup(app.Reset)

	now := time.Now()
	ip := net.IPv4(192, 0, 2, 10)
	mac, _ := net.ParseMAC("12:6c:d7:62:6c:2d")

	s := &scanner{
		group: interfaceGroup{
			iface: net.Interface{
				Name: "test0",
			},
		},

		expected: map[string]*pendingARP{
			ip.String(): {
				sentAt:   now.Add(-2 * time.Second),
				deadline: now.Add(-time.Second),
				retries:  1,
			},
		},

		found: make(map[string]arpHost),

		timeouts: timeout.New(),
	}

	app.Send(app.ARP)
	app.Retry(app.ARP)

	if !s.acceptReply(ip, mac) {
		t.Fatal("late ARP reply rejected")
	}

	if s.acceptReply(ip, mac) {
		t.Fatal("duplicate ARP reply accepted")
	}

	if len(s.expected) != 0 ||
		len(s.found) != 1 {
		t.Fatal("ARP reply did not finalize probe")
	}

	stats := app.Snapshot().ARP

	if stats.Received != 1 ||
		stats.TimedOut != 0 {
		t.Fatalf("incorrect ARP response count: %+v", stats)
	}
}

func TestARPReplyParsing(t *testing.T) {
	localIP := net.IPv4(192, 0, 2, 1)
	senderIP := net.IPv4(192, 0, 2, 10)

	localMAC, _ := net.ParseMAC(
		"4a:5b:b1:cc:f7:87",
	)

	senderMAC, _ := net.ParseMAC(
		"12:6c:d7:62:6c:2d",
	)

	frame := make([]byte, 42)

	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	binary.BigEndian.PutUint16(frame[20:22], 2)

	frame[18] = 6
	frame[19] = 4

	copy(frame[22:28], senderMAC)
	copy(frame[28:32], senderIP.To4())
	copy(frame[32:38], localMAC)
	copy(frame[38:42], localIP.To4())

	// An Ethernet source MAC can differ from
	// the ARP payload's sender hardware address.
	// Our earlier router capture showed this.
	relayMAC, _ := net.ParseMAC(
		"74:fe:ce:ff:f0:b9",
	)

	copy(frame[6:12], relayMAC)

	ip, mac, ok := parseReply(
		frame,
		localIP,
		localMAC,
	)

	if !ok ||
		!ip.Equal(senderIP) ||
		mac.String() != senderMAC.String() {
		t.Fatal("valid ARP reply rejected")
	}

	// An ARP request is not a valid reply.
	binary.BigEndian.PutUint16(frame[20:22], 1)

	_, _, ok = parseReply(
		frame,
		localIP,
		localMAC,
	)

	if ok {
		t.Fatal("ARP request accepted as reply")
	}
}
