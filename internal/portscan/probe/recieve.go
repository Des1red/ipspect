package probe

import (
	"encoding/binary"
	"net"
)

func (s *SYNScanner) readLoop() {
	buf := make(
		[]byte,
		65535,
	)

	for {
		header, payload, _, err :=
			s.raw.ReadFrom(buf)

		if err != nil {
			select {
			case s.errors <- err:
			default:
			}

			return
		}

		if header == nil ||
			header.Protocol != 6 ||
			len(payload) < 20 {

			continue
		}

		reply := Reply{
			SrcIP: append(
				net.IP(nil),
				header.Src...,
			),

			SrcPort: binary.BigEndian.Uint16(
				payload[0:2],
			),

			DstPort: binary.BigEndian.Uint16(
				payload[2:4],
			),

			seq: binary.BigEndian.Uint32(
				payload[4:8],
			),

			Ack: binary.BigEndian.Uint32(
				payload[8:12],
			),

			Flags: payload[13],
		}

		select {
		case s.replies <- reply:
		default:
		}
	}
}
