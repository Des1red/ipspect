package portscan

import (
	"ipspect/internal/models"
	"net"
)

func prioritizeTargets() {
	targets := models.INFO.Targets

	if len(targets) == 0 {
		return
	}

	allowed := make(
		map[string]net.IP,
		len(targets),
	)

	for _, ip := range targets {
		key := ip.String()

		if _, exists := allowed[key]; !exists {
			allowed[key] = ip
		}
	}

	ordered := make(
		[]net.IP,
		0,
		len(allowed),
	)

	seen := make(
		map[string]struct{},
		len(allowed),
	)

	add := func(ip net.IP) {
		key := ip.String()

		original, allowedTarget := allowed[key]

		if !allowedTarget {
			return
		}

		if _, exists := seen[key]; exists {
			return
		}

		seen[key] = struct{}{}

		ordered = append(
			ordered,
			original,
		)
	}

	/*
		Priority 1:
		ICMP-discovered hosts.
	*/

	for _, address := range models.LOOT.ICMPReachable {
		ip := net.ParseIP(address)

		if ip == nil {
			continue
		}

		add(ip)
	}

	/*
		Priority 2:
		ARP-discovered hosts.

		Already discovered hosts
		are ignored automatically.
	*/

	for _, address := range models.LOOT.ARPReachable {
		ip := net.ParseIP(address)

		if ip == nil {
			continue
		}

		add(ip)
	}

	/*
		Priority 3:
		Remaining original targets.

		No target is scanned twice.
	*/

	for _, ip := range targets {
		add(ip)
	}

	models.INFO.Targets = ordered

	models.TR.Single = len(ordered) == 1
	models.TR.Multi = len(ordered) > 1
}
