package models

import "net"

var DEBUG = true

type TargetRange struct {
	Multi  bool
	Single bool
}

var TR TargetRange

var INFO struct {
	TargetName string
	Targets    []net.IP

	PortStart int
	PortEnd   int

	Ports    []int
	PortSpec string
}
