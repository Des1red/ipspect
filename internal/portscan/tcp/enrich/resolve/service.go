package resolve

import "strings"

var serviceAliases = map[string]string{
	// DNS
	"domain": "dns",

	// HTTP
	"www":      "http",
	"www-http": "http",
	"http-alt": "http",

	// SMTP
	"submission": "smtp",
}

func sameService(
	registered string,
	detected string,
) bool {
	registered = strings.ToLower(
		strings.TrimSpace(registered),
	)

	detected = strings.ToLower(
		strings.TrimSpace(detected),
	)

	if registered == "" ||
		detected == "" ||
		registered == "unknown" ||
		detected == "unknown" {

		return false
	}

	if alias, ok := serviceAliases[registered]; ok {
		registered = alias
	}

	if alias, ok := serviceAliases[detected]; ok {
		detected = alias
	}

	return registered == detected
}
