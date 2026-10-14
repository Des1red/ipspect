package fingerprint

import (
	"bytes"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/fingerprint/analyzer/recog"
	"testing"
)

func TestAnalyzeBinaryTelnet(t *testing.T) {
	data := []byte{
		0xFF, 0xFD, 0x01,
		0xFF, 0xFD, 0x1F,
		0xFF, 0xFB, 0x01,
		0xFF, 0xFB, 0x03,
	}

	detail := &models.PortDetail{
		Port:        23,
		DBLookup:    "telnet",
		RawResponse: append([]byte(nil), data...),
	}

	session := &recog.Session{}

	match := analyzeBinary(
		detail,
		data,
		nil,
		session,
	)

	if match.Service != "telnet" {
		t.Fatalf(
			"expected telnet, got %q",
			match.Service,
		)
	}

	if match.Confidence != "high" {
		t.Fatalf(
			"unexpected confidence: %q",
			match.Confidence,
		)
	}

	if !bytes.Equal(detail.RawResponse, data) {
		t.Fatal("original response was modified")
	}
}

func TestAnalyzeBinaryNuclei(t *testing.T) {
	data := []byte{
		0x01, 0x02, 0x03, 0x04,
	}

	probe := requests.Probe{
		ID:      "test-binary",
		Service: "test-service",
		Matchers: []requests.Matcher{
			{
				Words: [][]byte{
					{0x01, 0x02, 0x03},
				},
				Condition: "or",
			},
		},
		Condition: "or",
	}

	detail := &models.PortDetail{
		Port: 12345,
	}

	session := &recog.Session{}

	match := analyzeBinary(
		detail,
		data,
		&probe,
		session,
	)

	if match.Service != "test-service" {
		t.Fatalf(
			"expected Nuclei signature match, got %q",
			match.Service,
		)
	}

	if match.Confidence != "medium" {
		t.Fatalf(
			"unexpected confidence: %q",
			match.Confidence,
		)
	}
}

func TestAnalyzeBinaryUnknown(t *testing.T) {
	data := []byte{
		0x01, 0x00, 0x03, 0x00,
	}

	detail := &models.PortDetail{
		Port: 12345,
	}

	session := &recog.Session{}

	match := analyzeBinary(
		detail,
		data,
		nil,
		session,
	)

	if match.Service != "" {
		t.Fatalf(
			"expected unknown, got %+v",
			match,
		)
	}
}
