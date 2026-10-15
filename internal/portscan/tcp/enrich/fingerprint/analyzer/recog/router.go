package recog

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"strings"
)

func protocolFamily(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "https":
		return "http"
	case "domain":
		return "dns"
	default:
		return strings.ToLower(strings.TrimSpace(service))
	}
}

func (s *Session) matchField(
	key string,
	value string,
	confirmedService string,
) models.FingerprintMatch {
	db := load.RecogDB(key)

	if db == nil || value == "" {
		return models.FingerprintMatch{}
	}

	databaseService := strings.ToLower(
		strings.TrimSpace(db.Protocol),
	)

	if confirmedService != "" &&
		databaseService != "" &&
		protocolFamily(confirmedService) !=
			protocolFamily(databaseService) {

		return models.FingerprintMatch{}
	}

	service := confirmedService

	if service == "" {
		service = databaseService
	}

	if service == "" {
		return models.FingerprintMatch{}
	}

	return s.lookup(
		key,
		service,
		value,
	)
}

func (s *Session) matchTypedFields(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	for _, field := range evidence.Fields {
		match := s.matchField(
			field.Key,
			field.Value,
			evidence.Service,
		)

		if match.Service != "" {
			return match
		}
	}

	return models.FingerprintMatch{}
}

func isBannerDatabase(key string) bool {
	// These databases expect normalized banner
	// values, not complete protocol greetings.
	// Existing protocol recognition handles
	// their extraction before routing.
	switch key {
	case "ssh.banner",
		"ftp.banner",
		"smtp.banner":

		return false
	}

	return strings.HasSuffix(key, ".banner") ||
		strings.HasSuffix(key, ".banners") ||
		strings.HasSuffix(key, "_banners")
}

func (s *Session) matchProtocolBanner(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	banner := strings.TrimSpace(evidence.Banner)

	if banner == "" {
		return models.FingerprintMatch{}
	}

	service := evidence.Service

	if service == "" {
		service = evidence.ServiceHint
	}

	if service == "" {
		return models.FingerprintMatch{}
	}

	for _, source := range load.RecogCatalog() {
		if !isBannerDatabase(source.Key) {
			continue
		}

		if protocolFamily(source.Protocol) !=
			protocolFamily(service) {

			continue
		}

		match := s.matchField(
			source.Key,
			banner,
			evidence.Service,
		)

		if match.Service == "" {
			continue
		}

		match.Banner = banner

		return match
	}

	return models.FingerprintMatch{}
}
