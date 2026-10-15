package models

import "strings"

type RecogSource string

const (
	RecogCapture RecogSource = "capture"
	RecogProbe   RecogSource = "probe"
	RecogBinary  RecogSource = "binary"
)

type RecogField struct {
	Key   string
	Value string
}

type RecogEvidence struct {
	Source RecogSource

	// Confirmed by protocol validation
	// or a matching active probe.
	Service string

	// Port-based hint, not confirmed.
	ServiceHint string

	Banner      string
	Headers     map[string][]string
	RawResponse []byte

	// Additional typed evidence.
	Fields []RecogField
}

func NewRecogEvidence(
	detail *PortDetail,
) RecogEvidence {
	headers := make(
		map[string][]string,
		len(detail.Headers),
	)

	for key, values := range detail.Headers {
		headers[key] = append(
			[]string(nil),
			values...,
		)
	}

	return RecogEvidence{
		Source:      RecogCapture,
		ServiceHint: detail.DBLookup,
		Banner:      detail.Banner,
		Headers:     headers,
		RawResponse: append(
			[]byte(nil),
			detail.RawResponse...,
		),
	}
}

func (e *RecogEvidence) AddField(
	key string,
	value string,
) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)

	if key == "" || value == "" {
		return
	}

	for _, field := range e.Fields {
		if field.Key == key &&
			field.Value == value {

			return
		}
	}

	e.Fields = append(
		e.Fields,
		RecogField{
			Key:   key,
			Value: value,
		},
	)
}
