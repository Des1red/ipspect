package search

import "ipspect/internal/models"

func recordPortState(
	hostIndex int,
	port int,
	state string,
) {
	host := &models.LOOT.Hosts[hostIndex]

	explicitPorts := len(models.INFO.Ports) > 0

	storePorts := models.TR.Single || explicitPorts

	switch state {
	case "open":
		host.Ports = append(
			host.Ports,
			port,
		)

		host.Details = append(
			host.Details,
			models.PortDetail{
				Port:  port,
				State: state,
			},
		)

	case "closed":
		host.ClosedCount++

		if storePorts {
			host.Closed = append(
				host.Closed,
				port,
			)
		}

		if explicitPorts {
			host.Details = append(
				host.Details,
				models.PortDetail{
					Port:  port,
					State: state,
				},
			)
		}

	case "filtered":
		host.FilteredCount++

		if storePorts {
			host.Filtered = append(
				host.Filtered,
				port,
			)
		}

		if explicitPorts {
			host.Details = append(
				host.Details,
				models.PortDetail{
					Port:  port,
					State: state,
				},
			)
		}
	}
}
