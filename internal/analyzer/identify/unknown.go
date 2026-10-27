package identify

import "fmt"

func DescribeUnknown(data []byte) string {
	if len(data) == 0 {
		return "No matching protocol signature"
	}

	preview := data
	if len(preview) > 32 {
		preview = preview[:32]
	}

	if IsBinaryResponse(data) {
		description := fmt.Sprintf(
			"Unrecognized binary response (%d captured bytes): % X",
			len(data),
			preview,
		)

		if len(data) > len(preview) {
			description += " ..."
		}

		return description
	}

	return fmt.Sprintf(
		"Unrecognized text response (%d captured bytes): %q",
		len(data),
		string(preview),
	)
}

func IsBinaryResponse(data []byte) bool {
	// VNC's server version greeting is printable ASCII, but it is a
	// protocol handshake consumed by the protocol decoder.
	if len(data) >= 12 &&
		string(data[:4]) == "RFB " &&
		data[7] == '.' &&
		data[11] == '\n' {
		return true
	}

	for _, b := range data {
		if b == '\r' || b == '\n' || b == '\t' {
			continue
		}

		if b < 0x20 || b > 0x7e {
			return true
		}
	}

	return false
}
