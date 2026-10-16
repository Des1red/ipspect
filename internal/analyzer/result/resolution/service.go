package resolution

import "ipspect/internal/service"

func sameService(
	registered string,
	detected string,
) bool {
	registered = service.Normalize(registered)
	detected = service.Normalize(detected)

	if registered == "" || detected == "" {
		return false
	}

	return registered == detected
}
