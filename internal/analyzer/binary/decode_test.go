package binary

import (
	"ipspect/internal/models"
	"testing"
)

func TestDecodeVNC(t *testing.T) {
	result := decode(models.BinaryEvidence{
		RawResponse: []byte("RFB 003.008\n"),
	})

	if result.Match.Service != "vnc" ||
		result.Match.Confidence != "high" ||
		result.Match.Banner != "RFB 003.008\n" {
		t.Fatalf("unexpected VNC result: %+v", result)
	}

	if got := decode(models.BinaryEvidence{
		RawResponse: []byte("RFB 003.009\n"),
	}); got.Match.Service != "" {
		t.Fatalf("accepted unsupported VNC version: %+v", got)
	}
}

func TestDecodeMySQLHandshake(t *testing.T) {
	payload := []byte{
		0x0a, '8', '.', '0', '.', '3', '6', 0,
		1, 0, 0, 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 0,
	}

	data := []byte{byte(len(payload)), 0, 0, 0}
	data = append(data, payload...)

	result := decode(models.BinaryEvidence{RawResponse: data})
	if result.Match.Service != "mysql" ||
		result.Match.Banner != "8.0.36" {
		t.Fatalf("unexpected MySQL result: %+v", result)
	}

	data[3] = 1
	if got := decode(models.BinaryEvidence{RawResponse: data}); got.Match.Service != "" {
		t.Fatalf("accepted non-initial MySQL packet: %+v", got)
	}
}

func TestDecodeRDPConfirmation(t *testing.T) {
	packet := []byte{3, 0, 0, 11, 6, 0xd0, 0, 0, 0, 0, 0}

	result := decode(models.BinaryEvidence{RawResponse: packet})
	if result.Match.Service != "rdp" ||
		result.Match.Confidence != "high" {
		t.Fatalf("unexpected RDP result: %+v", result)
	}

	packet[5] = 0xe0
	if got := decode(models.BinaryEvidence{RawResponse: packet}); got.Match.Service != "" {
		t.Fatalf("accepted non-confirmation X.224 packet: %+v", got)
	}
}
