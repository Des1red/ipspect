package binary

import (
	"fmt"
	"ipspect/internal/models"
	"strings"
)

const (
	telnetIAC  = 0xFF
	telnetSE   = 0xF0
	telnetSB   = 0xFA
	telnetWILL = 0xFB
	telnetWONT = 0xFC
	telnetDO   = 0xFD
	telnetDONT = 0xFE
)

func decode(
	evidence models.BinaryEvidence,
) models.BinaryResult {
	if len(evidence.RawResponse) == 0 {
		return models.BinaryResult{}
	}

	if result := decodeTelnet(
		evidence.RawResponse,
	); result.Match.Service != "" {

		return result
	}

	return models.BinaryResult{}
}

func decodeTelnet(
	data []byte,
) models.BinaryResult {
	if len(data) < 6 {
		return models.BinaryResult{}
	}

	var text strings.Builder

	negotiations := 0

	for i := 0; i < len(data); {
		if data[i] != telnetIAC {
			b := data[i]

			if b != '\r' &&
				b != '\n' &&
				b != '\t' &&
				(b < 0x20 || b > 0x7E) {

				return models.BinaryResult{}
			}

			if text.Len() < 512 {
				text.WriteByte(b)
			}

			i++
			continue
		}

		if i+1 >= len(data) {
			return models.BinaryResult{}
		}

		command := data[i+1]

		switch command {
		case telnetWILL,
			telnetWONT,
			telnetDO,
			telnetDONT:

			if i+2 >= len(data) {
				return models.BinaryResult{}
			}

			negotiations++
			i += 3

		case telnetSB:
			next, ok := skipTelnetSubnegotiation(
				data,
				i+2,
			)

			if !ok {
				return models.BinaryResult{}
			}

			i = next

		case telnetIAC:
			// Escaped IAC data byte.
			i += 2

		case 0xF1, 0xF2, 0xF3,
			0xF4, 0xF5, 0xF6,
			0xF7, 0xF8, 0xF9:

			// Two-byte Telnet commands.
			i += 2

		default:
			return models.BinaryResult{}
		}
	}

	// Require multiple valid negotiations
	// before confirming the protocol.
	if negotiations < 2 {
		return models.BinaryResult{}
	}

	result := models.BinaryResult{
		Match: models.FingerprintMatch{
			Service:    "telnet",
			Confidence: "high",
			Evidence: fmt.Sprintf(
				"Valid Telnet IAC negotiation (%d option commands)",
				negotiations,
			),
		},
	}

	banner := strings.TrimSpace(
		text.String(),
	)

	if banner != "" {
		result.Match.Banner = banner
		result.Recog.Banner = banner
	}

	return result
}

func skipTelnetSubnegotiation(
	data []byte,
	start int,
) (int, bool) {
	for i := start; i+1 < len(data); i++ {
		if data[i] != telnetIAC {
			continue
		}

		switch data[i+1] {
		case telnetIAC:
			i++

		case telnetSE:
			return i + 2, true

		default:
			return 0, false
		}
	}

	return 0, false
}
