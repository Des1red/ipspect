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
		return s.RecognizePassive(evidence)
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

			// Binary responses may still have
			// fields extracted by a decoder.
			return s.RecognizePassive(evidence)
		}
	}

	evidence.Banner = strings.TrimSpace(
		string(line),
	)

	return s.RecognizePassive(evidence)
}
