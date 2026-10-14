package models

type NucleiSearch struct {
	Target string
	Port   int

	DBLookup string

	Banner      string
	RawResponse []byte
	Headers     map[string][]string
}

func NewNucleiSearch(
	target string,
	detail *PortDetail,
) NucleiSearch {
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

	return NucleiSearch{
		Target: target,
		Port:   detail.Port,

		DBLookup: detail.DBLookup,

		Banner: detail.Banner,

		RawResponse: append(
			[]byte(nil),
			detail.RawResponse...,
		),

		Headers: headers,
	}
}
