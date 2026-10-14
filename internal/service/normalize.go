package service

import "strings"

var aliases = map[string]string{
	// DNS
	"domain": "dns",

	// HTTP
	"www":      "http",
	"www-http": "http",
	"http-alt": "http",

	// RDP
	"ms-wbt-server": "rdp",

	// SMB
	"microsoft-ds": "smb",
	"netbios-ssn":  "smb",

	// SMTP
	"submission":  "smtp",
	"submissions": "smtp",
	"smtps":       "smtp",

	// IMAP
	"imaps": "imap",

	// POP3
	"pop3s": "pop3",

	// PostgreSQL
	"postgres": "postgresql",
}

func Normalize(value string) string {
	value = strings.ToLower(
		strings.TrimSpace(value),
	)

	if value == "" || value == "unknown" {
		return ""
	}

	if alias, ok := aliases[value]; ok {
		return alias
	}

	return value
}
