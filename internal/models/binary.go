package models

type BinaryEvidence struct {
	Port        int
	DBLookup    string
	RawResponse []byte
}

type BinaryResult struct {
	Match FingerprintMatch
	Recog RecogEvidence
}

func NewBinaryEvidence(
	detail *PortDetail,
	response []byte,
) BinaryEvidence {
	return BinaryEvidence{
		Port:     detail.Port,
		DBLookup: detail.DBLookup,

		RawResponse: append(
			[]byte(nil),
			response...,
		),
	}
}
