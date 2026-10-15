package recog

import (
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
)

type lookupKey struct {
	key     string
	service string
	input   string
}

type Session struct {
	matches map[lookupKey]models.FingerprintMatch
}

func (s *Session) lookup(
	key string,
	service string,
	input string,
) models.FingerprintMatch {
	id := lookupKey{
		key:     key,
		service: service,
		input:   input,
	}

	if result, exists := s.matches[id]; exists {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.recog.cache: HIT db=%q service=%q input=%q matched=%t product=%q",
				key,
				service,
				input,
				result.Service != "",
				result.Product,
			),
		)

		return result
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.cache: MISS db=%q service=%q input=%q",
			key,
			service,
			input,
		),
	)

	result := matchRecog(
		key,
		service,
		input,
	)

	if s.matches == nil {
		s.matches = make(
			map[lookupKey]models.FingerprintMatch,
		)
	}

	s.matches[id] = result

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.cache: STORED db=%q matched=%t product=%q",
			key,
			result.Service != "",
			result.Product,
		),
	)

	return result
}
