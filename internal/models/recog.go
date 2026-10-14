package models

type RecogEvidence struct {
	Banner      string
	Headers     map[string][]string
	RawResponse []byte
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
		Banner: detail.Banner,

		Headers: headers,

		RawResponse: append(
			[]byte(nil),
			detail.RawResponse...,
		),
	}
}
