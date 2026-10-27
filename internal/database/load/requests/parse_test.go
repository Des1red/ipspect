package requests

import (
	"strings"
	"testing"
)

func TestParseRequestTemplateSupportsExchangesAndVariants(t *testing.T) {
	data := []byte(`id: sample-protocol-detect
info:
  severity: info
  tags: network,redis,detect
tcp:
  - host: ["{{Hostname}}"]
    port: 6379
    inputs:
      - data: "PING\\r\\n"
        type: text
        read: 64
      - data: "2b4f4b0d0a"
        type: hex
    matchers:
      - type: word
        words: ["+PONG"]
        negative: false
    extractors:
      - type: regex
  - host: ["tls://{{Host}}:{{Port}}"]
    inputs: []
    matchers:
      - type: word
        words: ["+PONG"]
`)

	probes := parseRequestTemplate(data)
	if len(probes) != 2 {
		t.Fatalf("got %d probes, want 2", len(probes))
	}

	if len(probes[0].Exchanges) != 2 ||
		string(probes[0].Exchanges[0].Payload) != "PING\\r\\n" ||
		probes[0].Exchanges[0].ReadSize != 64 {
		t.Fatalf("unexpected first probe exchanges: %+v", probes[0].Exchanges)
	}

	if probes[0].TLS ||
		!probes[1].TLS ||
		len(probes[1].Exchanges) != 0 {
		t.Fatalf("unexpected transport variants: %+v", probes)
	}
}

func TestBundledJDWPTemplateLoadsAsSequentialExchanges(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}

	for _, probe := range ForPort(5005) {
		if probe.ID != "jdwp-detect" {
			continue
		}

		if len(probe.Exchanges) != 2 ||
			probe.Exchanges[0].ReadSize != 14 ||
			probe.Exchanges[1].ReadSize != 1024 {
			t.Fatalf("unexpected bundled JDWP exchanges: %+v", probe.Exchanges)
		}
		return
	}

	t.Fatal("bundled JDWP template did not load")
}

func TestMatchResponseSupportsNegativeRule(t *testing.T) {
	probe := Probe{
		Condition: "and",
		Matchers: []Matcher{{
			Words:    [][]byte{[]byte("mysql")},
			Negative: true,
		}},
	}

	if !MatchResponse(probe, []byte("redis")) {
		t.Fatal("expected negative matcher to match absent word")
	}
	if MatchResponse(probe, []byte("mysql")) {
		t.Fatal("expected negative matcher to reject present word")
	}
}

func TestParseRequestTemplateRejectsDynamicInput(t *testing.T) {
	data := `id: dynamic-detect
info:
  severity: info
  tags: network,ssh,detect
tcp:
  - host: ["{{Hostname}}"]
    inputs:
      - data: "{{hex_decode(\"0102\")}}"
    matchers:
      - type: word
        words: ["SSH-"]
`

	if got := parseRequestTemplate([]byte(data)); len(got) != 0 {
		t.Fatalf("expected dynamic input to be rejected, got %d probes", len(got))
	}
}

func TestTemplateVariantsAreBounded(t *testing.T) {
	data := `id: too-many-variants-detect
info:
  severity: info
  tags: network,ssh,detect
tcp:
` + strings.Repeat(
		"  - host: [\"{{Hostname}}\"]\n    inputs: []\n    matchers:\n      - type: word\n        words: [\"SSH-\"]\n",
		17,
	)

	if got := parseRequestTemplate([]byte(data)); len(got) != 0 {
		t.Fatalf("expected over-limit variants to be rejected, got %d probes", len(got))
	}
}
