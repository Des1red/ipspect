package arp

import (
	"net"
)

func localInterfaces(
	targets []net.IP,
) ([]interfaceGroup, error) {
	interfaces, err := net.Interfaces()

	if err != nil {
		return nil, err
	}

	var groups []interfaceGroup

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagBroadcast == 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			len(iface.HardwareAddr) != 6 {

			continue
		}

		addresses, err := iface.Addrs()

		if err != nil {
			continue
		}

		for _, address := range addresses {
			network, ok :=
				address.(*net.IPNet)

			if !ok {
				continue
			}

			sourceIP := network.IP.To4()

			if sourceIP == nil {
				continue
			}

			groups = append(
				groups,
				interfaceGroup{
					iface: iface,

					sourceIP: append(
						net.IP(nil),
						sourceIP...,
					),

					network: network,
				},
			)
		}
	}

	assigned := make(
		map[string]struct{},
	)

	for _, target := range targets {
		ipv4 := target.To4()

		if ipv4 == nil {
			continue
		}

		key := ipv4.String()

		if _, exists := assigned[key]; exists {
			continue
		}

		for i := range groups {
			if !groups[i].network.Contains(ipv4) {
				continue
			}

			if ipv4.Equal(groups[i].sourceIP) {
				break
			}

			groups[i].targets = append(
				groups[i].targets,
				append(net.IP(nil), ipv4...),
			)

			assigned[key] = struct{}{}

			break
		}
	}

	active := make(
		[]interfaceGroup,
		0,
		len(groups),
	)

	for _, group := range groups {
		if len(group.targets) > 0 {
			active = append(
				active,
				group,
			)
		}
	}

	return active, nil
}
