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

func decode(evidence models.BinaryEvidence) models.BinaryResult {
	if len(evidence.RawResponse) == 0 {
		return models.BinaryResult{}
	}

	decoders := []func([]byte) models.BinaryResult{
		decodeTelnet,
		decodeVNC,
		decodeMySQL,
		decodeRDP,
	}

	for _, decoder := range decoders {
		if result := decoder(evidence.RawResponse); result.Match.Service != "" {
			return result
		}
	}

	return models.BinaryResult{}
}

func decodeVNC(data []byte) models.BinaryResult {
	if len(data) < 12 ||
		string(data[:4]) != "RFB " ||
		data[7] != '.' ||
		data[11] != '\n' {
		return models.BinaryResult{}
	}

	for _, i := range []int{4, 5, 6, 8, 9, 10} {
		if data[i] < '0' || data[i] > '9' {
			return models.BinaryResult{}
		}
	}

	major := int(data[4]-'0')*100 +
		int(data[5]-'0')*10 +
		int(data[6]-'0')

	minor := int(data[8]-'0')*100 +
		int(data[9]-'0')*10 +
		int(data[10]-'0')

	if major != 3 || minor < 3 || minor > 8 {
		return models.BinaryResult{}
	}

	version := string(data[:12])

	return models.BinaryResult{
		Match: models.FingerprintMatch{
			Service:    "vnc",
			Confidence: "high",
			Banner:     version,
			Evidence:   "Valid VNC server protocol version " + strings.TrimSpace(version),
		},
		Recog: models.RecogEvidence{
			Banner: version,
		},
	}
}

func decodeMySQL(data []byte) models.BinaryResult {
	if len(data) < 10 {
		return models.BinaryResult{}
	}

	packetLength := int(data[0]) |
		int(data[1])<<8 |
		int(data[2])<<16

	if data[3] != 0 ||
		packetLength < 7 ||
		packetLength+4 > len(data) ||
		data[4] != 10 {
		return models.BinaryResult{}
	}

	versionEnd := 5
	for versionEnd < packetLength+4 && data[versionEnd] != 0 {
		b := data[versionEnd]
		if b < 0x20 || b > 0x7e || versionEnd-5 >= 128 {
			return models.BinaryResult{}
		}
		versionEnd++
	}

	if versionEnd == 5 ||
		versionEnd >= packetLength+4 ||
		versionEnd+5 > packetLength+4 {
		return models.BinaryResult{}
	}

	version := string(data[5:versionEnd])

	return models.BinaryResult{
		Match: models.FingerprintMatch{
			Service:    "mysql",
			Confidence: "high",
			Banner:     version,
			Evidence:   "Valid MySQL initial handshake; server version " + version,
		},
		Recog: models.RecogEvidence{
			Banner: version,
		},
	}
}

func decodeRDP(data []byte) models.BinaryResult {
	if len(data) < 11 || data[0] != 3 || data[1] != 0 {
		return models.BinaryResult{}
	}

	totalLength := int(data[2])<<8 | int(data[3])
	li := int(data[4])

	if totalLength < 11 ||
		totalLength > len(data) ||
		li < 6 ||
		5+li > totalLength ||
		data[5] != 0xd0 {
		return models.BinaryResult{}
	}

	return models.BinaryResult{
		Match: models.FingerprintMatch{
			Service:    "rdp",
			Confidence: "high",
			Evidence:   "Valid RDP X.224 connection confirmation",
		},
	}
}

func decodeTelnet(data []byte) models.BinaryResult {
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
		case telnetWILL, telnetWONT, telnetDO, telnetDONT:
			if i+2 >= len(data) {
				return models.BinaryResult{}
			}
			negotiations++
			i += 3

		case telnetSB:
			next, ok := skipTelnetSubnegotiation(data, i+2)
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

	banner := strings.TrimSpace(text.String())
	if banner != "" {
		result.Match.Banner = banner
		result.Recog.Banner = banner
	}

	return result
}

func skipTelnetSubnegotiation(data []byte, start int) (int, bool) {
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
