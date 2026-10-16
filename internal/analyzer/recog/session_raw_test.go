package recog

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"reflect"
	"testing"
)

func TestSessionRawRecognition(t *testing.T) {
	if err := load.LoadRecog(); err != nil {
		t.Fatal(err)
	}

	session := &Session{}

	evidence := models.RecogEvidence{
		RawResponse: []byte(
			"SSH-2.0-dropbear_2017.75\r\n",
		),
	}

	first := session.RecognizeRaw(evidence)

	if first.Service != "ssh" {
		t.Fatalf(
			"expected SSH, got %+v",
			first,
		)
	}

	initial := len(session.matches)

	second := session.RecognizeRaw(evidence)

	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated recognition changed result")
	}

	if len(session.matches) != initial {
		t.Fatal("repeated recognition added a lookup")
	}

	// Binary data must not enter text recognition.
	binaryMatch := session.RecognizeRaw(
		models.RecogEvidence{
			RawResponse: []byte{
				0xFF, 0xFD, 0x01,
				0xFF, 0xFB, 0x03,
			},
		},
	)

	if binaryMatch.Service != "" {
		t.Fatalf(
			"expected no text recognition, got %+v",
			binaryMatch,
		)
	}

	if len(session.matches) != initial {
		t.Fatal("binary rejection modified cache")
	}
}
