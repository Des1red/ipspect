package enrich

import (
	"crypto/rand"
	"encoding/binary"
	"ipspect/internal/network/app"
	"net"
	"strings"
	"time"
)

func lookupNetBIOS(ip string) string {
	target := net.ParseIP(ip)

	if target == nil || target.To4() == nil {
		return ""
	}

	address := net.JoinHostPort(
		ip,
		"137",
	)

	conn, err := net.DialTimeout(
		"udp4",
		address,
		nameTimeout,
	)

	if err != nil {
		return ""
	}

	defer conn.Close()

	if err := conn.SetDeadline(
		time.Now().Add(nameTimeout),
	); err != nil {
		return ""
	}

	query, id, err := buildNodeStatusRequest()

	if err != nil {
		return ""
	}

	start := time.Now()

	app.Send(app.NetBIOS)

	written, err := conn.Write(query)

	if err != nil {
		app.Fail(app.NetBIOS, err)
		return ""
	}

	if written != len(query) {
		app.Drop(app.NetBIOS)
		return ""
	}

	buf := make([]byte, 1500)

	n, err := conn.Read(buf)

	if err != nil {
		app.Fail(app.NetBIOS, err)
		return ""
	}

	name := parseNodeStatus(
		buf[:n],
		id,
	)

	if name == "" {
		app.Drop(app.NetBIOS)
		return ""
	}

	app.Receive(
		app.NetBIOS,
		time.Since(start),
	)

	return name
}

func buildNodeStatusRequest() ([]byte, uint16, error) {
	var tx [2]byte

	if _, err := rand.Read(tx[:]); err != nil {
		return nil, 0, err
	}

	id := binary.BigEndian.Uint16(tx[:])

	packet := make(
		[]byte,
		12,
		50,
	)

	binary.BigEndian.PutUint16(
		packet[0:2],
		id,
	)

	binary.BigEndian.PutUint16(
		packet[4:6],
		1,
	)

	// Encoded NetBIOS wildcard '*'.
	packet = append(packet, 32)
	packet = append(packet, 'C', 'K')

	for i := 0; i < 30; i++ {
		packet = append(packet, 'A')
	}

	// Terminator, NBSTAT type, IN class.
	packet = append(
		packet,
		0,
		0, 0x21,
		0, 1,
	)

	return packet, id, nil
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

func parseNodeStatus(
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

		// Ignore group names.
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

		// Unique workstation name.
		if suffix == 0x00 {
			return raw
		}

		// Unique file-server name.
		if suffix == 0x20 && fallback == "" {
			fallback = raw
		}
	}

	return fallback
}
