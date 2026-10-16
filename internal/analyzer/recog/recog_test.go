package recog

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"strings"
	"testing"
)

func TestRecogPassiveSSH(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	detail := &models.PortDetail{
		Banner: "SSH-2.0-RomSShell_4.62",
	}

	match := session.RecognizePassive(
		models.NewRecogEvidence(detail),
	)

	if match.Service != "ssh" ||
		match.Confidence != "high" {

		t.Fatalf(
			"unexpected identification: %+v",
			match,
		)
	}

	if !strings.Contains(match.Product, "RomSShell") ||
		!strings.Contains(match.Product, "4.62") {

		t.Fatalf(
			"unexpected product: %q",
			match.Product,
		)
	}
}

func TestRecogHTTPServer(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	match := session.Enrich(
		models.FingerprintMatch{
			Service:    "http",
			Confidence: "high",
			Evidence:   "HTTP response to active request",
			Headers: map[string][]string{
				"Server": {"Apache/2.4.38 (Debian)"},
			},
		},
	)

	if !strings.Contains(match.Product, "Apache") ||
		!strings.Contains(match.Product, "2.4.38") {

		t.Fatalf(
			"unexpected HTTP product: %q",
			match.Product,
		)
	}

	if match.Confidence != "high" {
		t.Fatalf(
			"protocol confidence changed: %q",
			match.Confidence,
		)
	}
}

func TestRecogUnknownBinary(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	evidence := models.RecogEvidence{
		RawResponse: []byte{
			0x01, 0x00, 0x03, 0x00,
		},
	}

	result := session.RecognizeRaw(evidence)

	if result.Service != "" {
		t.Fatalf(
			"unexpected binary identification: %+v",
			result,
		)
	}
}

func TestRecogRawSSH(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	evidence := models.RecogEvidence{
		RawResponse: []byte(
			"SSH-2.0-RomSShell_4.62\r\n",
		),
	}

	match := session.RecognizeRaw(evidence)

	if match.Service != "ssh" ||
		match.Confidence != "high" {

		t.Fatalf(
			"unexpected raw identification: %+v",
			match,
		)
	}
}
