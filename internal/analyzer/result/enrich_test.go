package result

import (
	"ipspect/internal/analyzer/recog"
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"strings"
	"testing"
)

func TestEnrichCapturedEvidence(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	detail := &models.PortDetail{
		Banner: "SSH-2.0-RomSShell_4.62",
		RawResponse: []byte(
			"SSH-2.0-RomSShell_4.62\r\n",
		),
		Fingerprint: models.FingerprintResult{
			Service: "ssh",
			Matches: []models.FingerprintMatch{
				{
					Service:    "ssh",
					Confidence: "high",
					Evidence:   "SSH identification banner",
				},
			},
		},
	}

	session := &recog.Session{}

	EnrichCapturedEvidence(detail, session)

	fp := detail.Fingerprint

	if fp.Service != "ssh" ||
		fp.Confidence != "high" {

		t.Fatalf(
			"identification changed: %+v",
			fp,
		)
	}

	if !strings.Contains(fp.Product, "RomSShell") ||
		!strings.Contains(fp.Product, "4.62") {

		t.Fatalf(
			"expected product identity, got %q",
			fp.Product,
		)
	}

	firstEvidence := fp.Evidence

	EnrichCapturedEvidence(detail, session)

	if detail.Fingerprint.Evidence != firstEvidence {
		t.Fatalf(
			"enrichment duplicated evidence: %q",
			detail.Fingerprint.Evidence,
		)
	}
}

func TestEnrichDoesNotOverrideService(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	detail := &models.PortDetail{
		Banner: "SSH-2.0-RomSShell_4.62",
		Fingerprint: models.FingerprintResult{
			Service:    "ftp",
			Confidence: "medium",
			Product:    "existing product",
			Matches: []models.FingerprintMatch{
				{
					Service:    "ftp",
					Confidence: "medium",
					Product:    "existing product",
					Evidence:   "Confirmed FTP match",
				},
			},
		},
	}

	EnrichCapturedEvidence(
		detail,
		&recog.Session{},
	)

	fp := detail.Fingerprint

	if fp.Service != "ftp" ||
		fp.Product != "existing product" {

		t.Fatalf(
			"unexpected cross-protocol enrichment: %+v",
			fp,
		)
	}

	if fp.Confidence != "medium" {
		t.Fatalf(
			"confidence changed: %q",
			fp.Confidence,
		)
	}
}
