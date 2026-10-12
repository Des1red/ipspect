package search

import "ipspect/internal/models"

func scanPorts() []int {
	if len(models.INFO.Ports) > 0 {
		return models.INFO.Ports
	}

	ports := make(
		[]int,
		0,
		models.INFO.PortEnd-
			models.INFO.PortStart+1,
	)

	for port := models.INFO.PortStart; port <= models.INFO.PortEnd; port++ {
		ports = append(
			ports,
			port,
		)
	}

	return ports
}

func (s *scanState) advanceCursor() {
	s.portIndex++

	if s.portIndex < len(s.ports) {
		return
	}

	s.portIndex = 0
	s.hostIndex++

	if s.hostIndex >=
		len(models.INFO.Targets) {

		s.moreJobs = false
	}
}
