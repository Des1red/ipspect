package recog

import (
	"bytes"
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"strings"
)

func (s *Session) RecognizeRaw(
	evidence models.RecogEvidence,
) models.FingerprintMatch {
	data := evidence.RawResponse

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.raw: start source=%q service=%q raw_bytes=%d",
			evidence.Source,
			evidence.Service,
			len(data),
		),
	)

	if len(data) == 0 {
		output.Log(
			"debug",
			"tcp.recog.raw: no raw data; forwarding existing evidence to passive recognition",
		)

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
			output.Log(
				"debug",
				"tcp.recog.raw: binary first line; skipping text extraction",
			)

			return s.RecognizePassive(evidence)
		}
	}

	evidence.Banner = strings.TrimSpace(
		string(line),
	)

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.recog.raw: printable first line extracted banner=%q",
			evidence.Banner,
		),
	)

	return s.RecognizePassive(evidence)
}
