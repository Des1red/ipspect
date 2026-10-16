package arp

import (
	"ipspect/internal/network/timeout"
	"net"
	"sync"
	"time"
)

const (
	arpPacketsPerSecond = 500
	arpRetries          = 2
)

type interfaceGroup struct {
	iface    net.Interface
	sourceIP net.IP
	network  *net.IPNet
	targets  []net.IP
}

type arpHost struct {
	ip    net.IP
	mac   net.HardwareAddr
	iface string
}

type pendingARP struct {
	sentAt   time.Time
	deadline time.Time

	retries int
	queued  bool
}

type scanner struct {
	fd int

	group interfaceGroup

	expected map[string]*pendingARP
	found    map[string]arpHost

	missed int

	timeouts *timeout.Manager

	mu sync.Mutex

	done chan struct{}
	wg   sync.WaitGroup
}
