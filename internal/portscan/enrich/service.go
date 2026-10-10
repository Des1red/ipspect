package enrich

func lookupService(
	port int,
) string {
	if name, ok := commonPorts[port]; ok {
		return name
	}

	return "unknown"
}
