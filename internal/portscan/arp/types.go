package arp

import (
	"net"
	"sync"
	"time"
)

const (
	arpPacketsPerSecond = 500
	arpReplyWait        = 750 * time.Millisecond
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

type scanner struct {
	fd int

	group interfaceGroup

	expected map[string]struct{}
	found    map[string]arpHost

	mu sync.Mutex

	done chan struct{}
	wg   sync.WaitGroup
}
