package enrich

import (
	"crypto/rand"
	"encoding/binary"
	"ipspect/internal/analyzer"
	"ipspect/internal/network/app"
	"net"
	"time"
)

func lookupNetBIOS(
	ip string,
	engine *analyzer.Engine,
) string {
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

	name := engine.IdentifyNetBIOSResponse(
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

	packet = append(packet, 32)
	packet = append(packet, 'C', 'K')

	for i := 0; i < 30; i++ {
		packet = append(packet, 'A')
	}

	packet = append(
		packet,
		0,
		0, 0x21,
		0, 1,
	)

	return packet, id, nil
}
