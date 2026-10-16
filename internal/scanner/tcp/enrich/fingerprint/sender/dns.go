package sender

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"ipspect/internal/analyzer"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"net"
	"strconv"
	"time"
)

var dnsQuestion = []byte{
	7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	3, 'c', 'o', 'm', 0,
	0, 1, // A record
	0, 1, // IN class
}

func ProbeDNS(
	ip string,
	port int,
	engine *analyzer.Engine,
) models.FingerprintMatch {
	var tx [2]byte

	if _, err := rand.Read(tx[:]); err != nil {
		return models.FingerprintMatch{}
	}

	request := make(
		[]byte,
		12+len(dnsQuestion),
	)

	copy(request[0:2], tx[:])

	binary.BigEndian.PutUint16(
		request[2:4],
		0x0100,
	)

	binary.BigEndian.PutUint16(
		request[4:6],
		1,
	)

	copy(
		request[12:],
		dnsQuestion,
	)

	// DNS over TCP requires a two-byte
	// message-length prefix.
	frame := make(
		[]byte,
		2+len(request),
	)

	binary.BigEndian.PutUint16(
		frame[:2],
		uint16(len(request)),
	)

	copy(frame[2:], request)

	address := net.JoinHostPort(
		ip,
		strconv.Itoa(port),
	)

	connectStart := time.Now()

	app.Send(app.TCPConnect)

	conn, err := net.DialTimeout(
		"tcp",
		address,
		probeTimeout,
	)

	if err != nil {
		app.Fail(app.TCPConnect, err)
		return models.FingerprintMatch{}
	}

	app.Receive(
		app.TCPConnect,
		time.Since(connectStart),
	)

	defer conn.Close()

	if err = conn.SetDeadline(
		time.Now().Add(probeTimeout),
	); err != nil {
		return models.FingerprintMatch{}
	}

	requestStart := time.Now()

	app.Send(app.DNSTCP)

	written, err := conn.Write(frame)

	if err != nil {
		app.Fail(app.DNSTCP, err)
		return models.FingerprintMatch{}
	}

	if written != len(frame) {
		app.Drop(app.DNSTCP)
		return models.FingerprintMatch{}
	}

	var size [2]byte

	if _, err = io.ReadFull(
		conn,
		size[:],
	); err != nil {
		app.Fail(app.DNSTCP, err)
		return models.FingerprintMatch{}
	}

	n := int(
		binary.BigEndian.Uint16(size[:]),
	)

	if n < 12+len(dnsQuestion) ||
		n > 4096 {

		app.Drop(app.DNSTCP)
		return models.FingerprintMatch{}
	}

	response := make([]byte, n)

	if _, err = io.ReadFull(
		conn,
		response,
	); err != nil {
		app.Fail(app.DNSTCP, err)
		return models.FingerprintMatch{}
	}

	match, valid := engine.IdentifyDNSResponse(
		response,
		tx,
		dnsQuestion,
	)

	if !valid {
		app.Drop(app.DNSTCP)
		return models.FingerprintMatch{}
	}

	app.Receive(
		app.DNSTCP,
		time.Since(requestStart),
	)

	return match
}
