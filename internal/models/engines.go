package models

type engines struct {
	ICMP bool
	ARP  bool
	TCP  bool
}

var ActiveEngines = engines{}
