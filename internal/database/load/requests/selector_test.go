package requests

import (
	"ipspect/internal/models"
	"reflect"
	"testing"
)

func TestForEvidence(t *testing.T) {
	original := requestsDB

	t.Cleanup(func() {
		requestsDB = original
	})

	requestsDB = []Probe{
		{
			ID:      "redis",
			Service: "redis",
			Ports:   []int{6379},
			Matchers: []Matcher{
				{
					Words: [][]byte{
						[]byte("-ERR"),
					},
				},
			},
		},
		{
			ID:      "vnc",
			Service: "vnc",
			Ports:   []int{5900},
			Matchers: []Matcher{
				{
					Words: [][]byte{
						[]byte("RFB 003"),
					},
				},
			},
		},
		{
			ID:      "rtsp",
			Service: "rtsp",
			Ports:   []int{8080},
			Matchers: []Matcher{
				{
					Words: [][]byte{
						[]byte("RTSP/1.0"),
					},
				},
			},
		},
	}

	search := models.NucleiSearch{
		Port:        8080,
		DBLookup:    "redis",
		RawResponse: []byte("RFB 003.008\n"),
	}

	probes := ForEvidence(search)

	got := []string{
		probes[0].ID,
		probes[1].ID,
		probes[2].ID,
	}

	want := []string{
		"vnc",
		"redis",
		"rtsp",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"got %v, want %v",
			got,
			want,
		)
	}
}
