package probe

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type Reply struct {
	SrcIP   net.IP
	SrcPort uint16
	DstPort uint16
	seq     uint32
	Ack     uint32
	Flags   byte
}

type SYNScanner struct {
	conn net.PacketConn
	raw  *ipv4.RawConn

	replies chan Reply
	errors  chan error

	closeOnce sync.Once

	sourceMu    sync.Mutex
	sourceCache map[string]net.IP

	nextPort uint16
	nextSeq  uint32
}

func NewSYNScanner() (*SYNScanner, error) {
	conn, err := net.ListenPacket(
		"ip4:tcp",
		"0.0.0.0",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open raw TCP socket: %w",
			err,
		)
	}

	raw, err := ipv4.NewRawConn(conn)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf(
			"prepare raw IPv4 socket: %w",
			err,
		)
	}

	s := &SYNScanner{
		conn: conn,
		raw:  raw,

		replies: make(
			chan Reply,
			2048,
		),

		errors: make(
			chan error,
			1,
		),

		sourceCache: make(
			map[string]net.IP,
		),

		nextPort: 49152,
		nextSeq:  0x6a09e667,
	}

	go s.readLoop()

	return s, nil
}

func (s *SYNScanner) Close() error {
	var err error

	s.closeOnce.Do(func() {
		err = s.conn.Close()
	})

	return err
}

func (s *SYNScanner) Replies() <-chan Reply {
	return s.replies
}

func (s *SYNScanner) Errors() <-chan error {
	return s.errors
}
