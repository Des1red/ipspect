package recog

import (
	"fmt"
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"ipspect/internal/output"
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
	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.router: field key=%q confirmed_service=%q input=%q",
			key,
			confirmedService,
			value,
		),
	)

	db := load.RecogDB(key)

	if db == nil {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.router: skipped key=%q reason=database-not-loaded",
				key,
			),
		)

		return models.FingerprintMatch{}
	}

	if value == "" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.router: skipped key=%q reason=empty-value",
				key,
			),
		)

		return models.FingerprintMatch{}
	}

	databaseService := strings.ToLower(
		strings.TrimSpace(db.Protocol),
	)

	if confirmedService != "" &&
		databaseService != "" &&
		protocolFamily(confirmedService) !=
			protocolFamily(databaseService) {

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.router: rejected key=%q database_protocol=%q confirmed_service=%q reason=protocol-mismatch",
				key,
				databaseService,
				confirmedService,
			),
		)

		return models.FingerprintMatch{}
	}

	service := confirmedService

	if service == "" {
		service = databaseService
	}

	if service == "" {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.router: skipped key=%q reason=no-service",
				key,
			),
		)

		return models.FingerprintMatch{}
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.router: selected db=%q service=%q protocol=%q",
			key,
			service,
			databaseService,
		),
	)

	return s.lookup(
		key,
		service,
		value,
	)
}

func (s *Session) matchTypedFields(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.router: checking %d typed fields service=%q",
			len(evidence.Fields),
			evidence.Service,
		),
	)

	for _, field := range evidence.Fields {
		match := s.matchField(
			field.Key,
			field.Value,
			evidence.Service,
		)

		if match.Service != "" {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.recog.router: typed field matched key=%q service=%q product=%q",
					field.Key,
					match.Service,
					match.Product,
				),
			)

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
		output.Log(
			"debug",
			"tcp.recog.router: banner routing skipped reason=empty-banner",
		)

		return models.FingerprintMatch{}
	}

	service := evidence.Service

	if service == "" {
		service = evidence.ServiceHint
	}

	if service == "" {
		output.Log(
			"debug",
			"tcp.recog.router: banner routing skipped reason=no-service-or-hint",
		)

		return models.FingerprintMatch{}
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.router: searching banner databases service=%q confirmed=%q hint=%q",
			service,
			evidence.Service,
			evidence.ServiceHint,
		),
	)

	for _, source := range load.RecogCatalog() {
		if !isBannerDatabase(source.Key) {
			continue
		}

		if protocolFamily(source.Protocol) !=
			protocolFamily(service) {

			continue
		}

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.router: banner candidate db=%q file=%q protocol=%q",
				source.Key,
				source.File,
				source.Protocol,
			),
		)

		match := s.matchField(
			source.Key,
			banner,
			evidence.Service,
		)

		if match.Service == "" {
			output.Log(
				"debug",
				fmt.Sprintf(
					"tcp.recog.router: banner database no match key=%q",
					source.Key,
				),
			)

			continue
		}

		match.Banner = banner

		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.router: banner matched db=%q service=%q product=%q",
				source.Key,
				match.Service,
				match.Product,
			),
		)

		return match
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.router: no compatible banner signature matched service=%q",
			service,
		),
	)

	return models.FingerprintMatch{}
}
