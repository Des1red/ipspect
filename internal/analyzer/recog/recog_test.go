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

func TestRecogCatalogRoutesServiceBanners(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		service string
		banner  string
	}{
		{service: "imap", banner: "Dovecot ready."},
		{service: "nntp", banner: "CCProxy NNTP Service"},
		{
			service: "pop3",
			banner:  "Microsoft Exchange Server 2007 POP3 service ready",
		},
		{service: "mysql", banner: "8.0.36"},
	}

	for _, test := range tests {
		t.Run(test.service, func(t *testing.T) {
			match := (&Session{}).RecognizePassive(
				models.RecogEvidence{
					ServiceHint: test.service,
					Banner:      test.banner,
				},
			)

			if match.Service != test.service {
				t.Fatalf("expected %s, got %+v", test.service, match)
			}
		})
	}
}

func TestRecogHTTPHeaderDatabaseRouting(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	match := (&Session{}).RecognizePassive(
		models.RecogEvidence{
			ServiceHint: "http",
			Banner:      "HTTP/1.1 200 OK",
			Headers: map[string][]string{
				"X-Powered-By": {"PHP/8.2.14"},
			},
		},
	)

	if match.Service != "http" ||
		!strings.Contains(match.Product, "PHP") ||
		!strings.Contains(match.Product, "8.2.14") {
		t.Fatalf("unexpected HTTP header fingerprint: %+v", match)
	}
}
