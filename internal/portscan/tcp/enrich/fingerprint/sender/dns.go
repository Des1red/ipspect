package sender

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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
		app.TimeoutOnError(
			app.TCPConnect,
			err,
		)

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

	if _, err = conn.Write(frame); err != nil {
		app.TimeoutOnError(
			app.DNSTCP,
			err,
		)

		return models.FingerprintMatch{}
	}

	app.Send(app.DNSTCP)

	var size [2]byte

	if _, err = io.ReadFull(
		conn,
		size[:],
	); err != nil {
		app.TimeoutOnError(
			app.DNSTCP,
			err,
		)

		return models.FingerprintMatch{}
	}

	n := int(
		binary.BigEndian.Uint16(size[:]),
	)

	if n < 12+len(dnsQuestion) ||
		n > 4096 {

		return models.FingerprintMatch{}
	}

	response := make([]byte, n)

	if _, err = io.ReadFull(
		conn,
		response,
	); err != nil {
		app.TimeoutOnError(
			app.DNSTCP,
			err,
		)

		return models.FingerprintMatch{}
	}

	// Validate transaction ID.
	if !bytes.Equal(
		response[:2],
		tx[:],
	) {
		return models.FingerprintMatch{}
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

		return models.FingerprintMatch{}
	}

	// Require the server to echo the
	// original question.
	if !bytes.EqualFold(
		response[12:12+len(dnsQuestion)],
		dnsQuestion,
	) {
		return models.FingerprintMatch{}
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

	app.Receive(
		app.DNSTCP,
		time.Since(requestStart),
	)

	return models.FingerprintMatch{
		Service:    "dns",
		Confidence: "high",

		Evidence: "Valid DNS-over-TCP response " +
			"(RCODE=" + label + ")",
	}
}
