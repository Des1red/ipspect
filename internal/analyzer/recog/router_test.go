package recog

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"strings"
	"testing"
)

func TestRouterTypedField(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	evidence := models.RecogEvidence{
		Fields: []models.RecogField{
			{
				Key:   "ssh.banner",
				Value: "RomSShell_4.62",
			},
		},
	}

	match := session.RecognizePassive(evidence)

	if match.Service != "ssh" {
		t.Fatalf(
			"expected SSH, got %+v",
			match,
		)
	}

	if !strings.Contains(
		match.Product,
		"RomSShell",
	) {
		t.Fatalf(
			"unexpected product: %q",
			match.Product,
		)
	}
}

func TestRouterServiceMismatch(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	evidence := models.RecogEvidence{
		Service: "ftp",
		Fields: []models.RecogField{
			{
				Key:   "ssh.banner",
				Value: "RomSShell_4.62",
			},
		},
	}

	match := session.RecognizePassive(evidence)

	if match.Service != "" {
		t.Fatalf(
			"unexpected cross-protocol match: %+v",
			match,
		)
	}
}

func TestRouterPreservesSSH(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	match := session.RecognizePassive(
		models.RecogEvidence{
			Banner: "SSH-2.0-RomSShell_4.62",
		},
	)

	if match.Service != "ssh" ||
		match.Confidence != "high" {

		t.Fatalf(
			"SSH behavior changed: %+v",
			match,
		)
	}
}

func TestRouterUnknownEvidence(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	match := session.RecognizePassive(
		models.RecogEvidence{
			ServiceHint: "telnet",
			Banner:      "completely unknown banner",
		},
	)

	if match.Service != "" {
		t.Fatalf(
			"unexpected identification: %+v",
			match,
		)
	}
}
