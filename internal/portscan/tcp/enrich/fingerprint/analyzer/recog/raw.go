package recog

import (
	"bytes"
	"ipspect/internal/models"
	"strings"
)

func RecognizeRaw(
	data []byte,
) models.FingerprintMatch {
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

	return RecognizePassive(
		&models.PortDetail{
			Banner: strings.TrimSpace(
				string(line),
			),
		},
	)
}
