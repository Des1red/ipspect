package recog

import (
	"bytes"
	"ipspect/internal/models"
	"strings"
)

func (s *Session) RecognizeRaw(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	data := evidence.RawResponse

	if len(data) == 0 {
		return models.FingerprintMatch{}
	}

	line := data

	if index := bytes.IndexByte(
		line,
		'\n',
	); index >= 0 {

		line = line[:index]
	}

	for _, b := range line {
		if b != '\r' &&
			b != '\t' &&
			(b < 0x20 || b > 0x7e) {

			return models.FingerprintMatch{}
		}
	}

	return s.RecognizePassive(
		models.RecogEvidence{
			Banner: strings.TrimSpace(
				string(line),
			),
		},
	)
}
