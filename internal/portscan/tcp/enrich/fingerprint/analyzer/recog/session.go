package recog

import "ipspect/internal/models"

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
		return result
	}

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

	return result
}
