package requests

import (
	"strconv"
	"strings"
)

var requestServices = map[string]string{
	"redis":      "redis",
	"memcached":  "memcached",
	"mongodb":    "mongodb",
	"mysql":      "mysql",
	"postgres":   "postgresql",
	"postgresql": "postgresql",
	"ssh":        "ssh",
	"ftp":        "ftp",
	"smtp":       "smtp",
	"imap":       "imap",
	"pop3":       "pop3",
	"vnc":        "vnc",
	"rdp":        "rdp",
	"rtsp":       "rtsp",
	"mqtt":       "mqtt",
	"kafka":      "kafka",
	"jdwp":       "jdwp",
	"zookeeper":  "zookeeper",
	"rsync":      "rsync",
	"smb":        "smb",
	"telnet":     "telnet",
	"gopher":     "gopher",
	"ldap":       "ldap",
}

func serviceFromTags(tags string) string {
	for _, tag := range strings.Split(
		strings.ToLower(tags),
		",",
	) {
		tag = strings.TrimSpace(tag)

		if service, ok := requestServices[tag]; ok {
			return service
		}
	}

	return ""
}

func hasDetectionTag(tags string) bool {
	for _, tag := range strings.Split(
		strings.ToLower(tags),
		",",
	) {
		switch strings.TrimSpace(tag) {
		case "detect", "detection", "discovery":
			return true
		}
	}

	return false
}

func normalizeCondition(value string) (string, bool) {
	switch strings.ToLower(value) {
	case "", "or":
		return "or", true
	case "and":
		return "and", true
	}

	return "", false
}

func appendUniqueBool(values []bool, value bool) []bool {
	for _, current := range values {
		if current == value {
			return values
		}
	}

	return append(values, value)
}

func parseRequestPorts(value string) []int {
	var ports []int

	for _, part := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))

		if err != nil || port < 1 || port > 65535 {
			continue
		}

		ports = append(ports, port)
	}

	return ports
}
