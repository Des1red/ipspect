package identify

import (
	"encoding/binary"
	"strings"
)

func IdentifyNetBIOSResponse(
	data []byte,
	id uint16,
) string {
	if len(data) < 12 ||
		binary.BigEndian.Uint16(data[0:2]) != id {
		return ""
	}

	flags := binary.BigEndian.Uint16(
		data[2:4],
	)

	if flags&0x8000 == 0 ||
		flags&0x0200 != 0 ||
		flags&0x000f != 0 {
		return ""
	}

	questions := int(
		binary.BigEndian.Uint16(data[4:6]),
	)

	answers := int(
		binary.BigEndian.Uint16(data[6:8]),
	)

	if questions > 16 || answers > 32 {
		return ""
	}

	offset := 12

	for i := 0; i < questions; i++ {
		next, ok := skipDNSName(
			data,
			offset,
		)

		if !ok || next+4 > len(data) {
			return ""
		}

		offset = next + 4
	}

	for i := 0; i < answers; i++ {
		next, ok := skipDNSName(
			data,
			offset,
		)

		if !ok || next+10 > len(data) {
			return ""
		}

		rrtype := binary.BigEndian.Uint16(
			data[next : next+2],
		)

		rrclass := binary.BigEndian.Uint16(
			data[next+2 : next+4],
		)

		length := int(
			binary.BigEndian.Uint16(
				data[next+8 : next+10],
			),
		)

		offset = next + 10

		if length > len(data)-offset {
			return ""
		}

		if rrtype == 0x21 && rrclass == 1 {
			return nodeName(
				data[offset : offset+length],
			)
		}

		offset += length
	}

	return ""
}

func skipDNSName(
	data []byte,
	offset int,
) (int, bool) {
	for hops := 0; hops < 128; hops++ {
		if offset >= len(data) {
			return 0, false
		}

		size := int(data[offset])

		if size&0xc0 == 0xc0 {
			if offset+1 >= len(data) {
				return 0, false
			}

			return offset + 2, true
		}

		if size&0xc0 != 0 {
			return 0, false
		}

		offset++

		if size == 0 {
			return offset, true
		}

		if offset+size > len(data) {
			return 0, false
		}

		offset += size
	}

	return 0, false
}

func nodeName(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	count := int(data[0])

	if count == 0 ||
		count > (len(data)-1)/18 {
		return ""
	}

	var fallback string

	for i := 0; i < count; i++ {
		pos := 1 + i*18

		record := data[pos : pos+18]

		suffix := record[15]

		flags := binary.BigEndian.Uint16(
			record[16:18],
		)

		if flags&0x8000 != 0 {
			continue
		}

		raw := strings.TrimSpace(
			string(record[:15]),
		)

		if raw == "" {
			continue
		}

		valid := true

		for j := 0; j < len(raw); j++ {
			if raw[j] < 0x20 ||
				raw[j] > 0x7e {

				valid = false
				break
			}
		}

		if !valid {
			continue
		}

		if suffix == 0x00 {
			return raw
		}

		if suffix == 0x20 && fallback == "" {
			fallback = raw
		}
	}

	return fallback
}
