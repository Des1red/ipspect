package requests

import (
	"bytes"
	"encoding/hex"
	"strings"

	"gopkg.in/yaml.v3"
)

func parseRequestTemplate(data []byte) []Probe {
	if len(data) > 64<<10 {
		return nil
	}

	var tmpl requestTemplate
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	// Reject fields we haven't implemented.
	decoder.KnownFields(true)

	if err := decoder.Decode(&tmpl); err != nil {
		return nil
	}

	severity, _ := tmpl.Info["severity"].(string)
	if !strings.EqualFold(severity, "info") {
		return nil
	}

	tags, _ := tmpl.Info["tags"].(string)
	service := serviceFromTags(tags)
	if service == "" {
		return nil
	}

	lowerID := strings.ToLower(tmpl.ID)
	if lowerID == "" ||
		strings.HasPrefix(lowerID, "cve-") ||
		!hasDetectionTag(tags) {
		return nil
	}

	requests := tmpl.TCP
	if len(requests) == 0 {
		requests = tmpl.Network
	} else if len(tmpl.Network) != 0 {
		return nil
	}

	// Each TCP block is an independent request variant. Inputs within a block
	// are sequential exchanges, as in Nuclei's network templates.
	if len(requests) > 16 {
		return nil
	}

	var probes []Probe
	for _, request := range requests {
		probe, ok := compileRequest(tmpl.ID, service, request)
		if ok {
			probes = append(probes, probe...)
		}
	}

	return probes
}

func compileRequest(id, service string, request templateTCP) ([]Probe, bool) {
	if request.ReadAll ||
		len(request.Inputs) > 8 ||
		len(request.Matchers) == 0 {
		return nil, false
	}

	readSize := request.ReadSize
	if readSize == 0 {
		readSize = 1024
	}
	if readSize < 1 || readSize > 4096 {
		return nil, false
	}

	var exchanges []Exchange
	totalPayload := 0
	totalRead := 0

	for _, input := range request.Inputs {
		if input.Data == "" ||
			strings.Contains(input.Data, "{{") ||
			strings.Contains(input.Data, "}}") {
			return nil, false
		}

		var payload []byte
		switch strings.ToLower(input.Type) {
		case "", "text":
			payload = []byte(input.Data)

		case "hex":
			decoded, err := hex.DecodeString(strings.TrimSpace(input.Data))
			if err != nil {
				return nil, false
			}
			payload = decoded

		default:
			return nil, false
		}

		if len(payload) == 0 || len(payload) > 2048 {
			return nil, false
		}

		inputRead := input.Read
		if inputRead == 0 {
			inputRead = readSize
		}
		if inputRead < 1 || inputRead > 4096 {
			return nil, false
		}

		totalPayload += len(payload)
		totalRead += inputRead
		if totalPayload > 4096 || totalRead > 8192 {
			return nil, false
		}

		exchanges = append(exchanges, Exchange{
			Payload:  payload,
			ReadSize: inputRead,
		})
	}

	condition, ok := normalizeCondition(request.MatchersCondition)
	if !ok {
		return nil, false
	}

	var matchers []Matcher
	for _, raw := range request.Matchers {
		matcher, ok := compileMatcher(raw)
		if !ok {
			return nil, false
		}
		matchers = append(matchers, matcher)
	}

	var transports []bool
	for _, host := range request.Host {
		switch host {
		case "{{Hostname}}", "{{Host}}", "{{Host}}:{{Port}}":
			transports = appendUniqueBool(transports, false)

		case "tls://{{Hostname}}", "tls://{{Host}}", "tls://{{Host}}:{{Port}}":
			transports = appendUniqueBool(transports, true)
		}
	}
	if len(transports) == 0 {
		return nil, false
	}

	var firstPayload []byte
	if len(exchanges) > 0 {
		firstPayload = exchanges[0].Payload
	}

	probes := make([]Probe, 0, len(transports))
	for _, secure := range transports {
		probes = append(probes, Probe{
			ID:        id,
			Service:   service,
			TLS:       secure,
			Payload:   firstPayload,
			ReadSize:  readSize,
			Exchanges: exchanges,
			Ports:     parseRequestPorts(request.Port),
			Matchers:  matchers,
			Condition: condition,
		})
	}

	return probes, true
}
