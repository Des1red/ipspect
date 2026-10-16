package identify

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"ipspect/internal/models"
)

func IdentifyDNSResponse(
	response []byte,
	transactionID [2]byte,
	question []byte,
) (models.FingerprintMatch, bool) {
	if len(response) < 12+len(question) {
		return models.FingerprintMatch{}, false
	}

	// Validate transaction ID.
	if !bytes.Equal(
		response[:2],
		transactionID[:],
	) {
		return models.FingerprintMatch{}, false
	}

	flags := binary.BigEndian.Uint16(
		response[2:4],
	)

	// Must be a standard DNS response,
	// with the expected question count.
	if flags&0x8000 == 0 ||
		flags&0x7800 != 0 ||
		binary.BigEndian.Uint16(
			response[4:6],
		) != 1 {

		return models.FingerprintMatch{}, false
	}

	// Require the server to echo the
	// original question.
	if !bytes.EqualFold(
		response[12:12+len(question)],
		question,
	) {
		return models.FingerprintMatch{}, false
	}

	rcode := int(flags & 0x000f)

	names := []string{
		"NOERROR",
		"FORMERR",
		"SERVFAIL",
		"NXDOMAIN",
		"NOTIMP",
		"REFUSED",
	}

	label := fmt.Sprintf(
		"%d",
		rcode,
	)

	if rcode < len(names) {
		label = names[rcode]
	}

	return models.FingerprintMatch{
		Service:    "dns",
		Confidence: "high",

		Evidence: "Valid DNS-over-TCP response " +
			"(RCODE=" + label + ")",
	}, true
}
