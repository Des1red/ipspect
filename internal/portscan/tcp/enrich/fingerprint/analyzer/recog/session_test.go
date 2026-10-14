package recog

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"reflect"
	"strings"
	"testing"
)

func TestSessionRecognizePassive(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	evidence := models.RecogEvidence{
		Banner: "SSH-2.0-dropbear_2017.75",
	}

	first := session.RecognizePassive(evidence)

	if first.Service != "ssh" {
		t.Fatalf(
			"expected ssh, got %+v",
			first,
		)
	}

	if first.Product == "" {
		t.Fatal("expected identified SSH product")
	}

	if !strings.Contains(
		first.Evidence,
		"Rapid7 Recog [",
	) {
		t.Fatalf(
			"missing Recog evidence: %q",
			first.Evidence,
		)
	}

	initial := len(session.matches)

	second := session.RecognizePassive(evidence)

	if !reflect.DeepEqual(first, second) {
		t.Fatal("cached recognition changed result")
	}

	if len(session.matches) != initial {
		t.Fatal("repeated recognition added a lookup")
	}

	enriched := session.Enrich(
		models.FingerprintMatch{
			Service: "ssh",
			Banner:  evidence.Banner,
		},
	)

	if enriched.Product != first.Product {
		t.Fatalf(
			"product changed: %q != %q",
			enriched.Product,
			first.Product,
		)
	}

	if len(session.matches) != initial {
		t.Fatal("enrichment did not reuse cached lookup")
	}

	if initial != 1 {
		t.Fatalf(
			"expected one cached lookup, got %d",
			initial,
		)
	}
}

func TestSessionUnknownReuse(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	banner := "SSH-2.0-IPSpectUnknownServer_123"

	first := session.RecognizePassive(
		models.RecogEvidence{
			Banner: banner,
		},
	)

	if first.Service != "" {
		t.Fatalf(
			"expected unknown, got %+v",
			first,
		)
	}

	session.Enrich(
		models.FingerprintMatch{
			Service: "ssh",
			Banner:  banner,
		},
	)

	if len(session.matches) != 1 {
		t.Fatalf(
			"expected cached negative lookup, got %d",
			len(session.matches),
		)
	}
}
