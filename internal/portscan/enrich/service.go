package enrich

func lookupService(
	port int,
) string {
	if name, ok := serviceNames[port]; ok {
		return name
	}

	return "unknown"
}
