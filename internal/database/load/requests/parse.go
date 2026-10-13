package requests

import (
	"bytes"
	"encoding/hex"
	"strings"

	"gopkg.in/yaml.v3"
)

func parseRequestTemplate(
	data []byte,
) []Probe {
	if len(data) > 64<<10 {
		return nil
	}

	var tmpl requestTemplate

	decoder := yaml.NewDecoder(
		bytes.NewReader(data),
	)

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

	// Only independent, single-request templates.
	if len(requests) != 1 {
		return nil
	}

	request := requests[0]

	if request.ReadAll ||
		len(request.Inputs) != 1 ||
		len(request.Matchers) == 0 {

		return nil
	}

	input := request.Inputs[0]

	if input.Data == "" ||
		strings.Contains(input.Data, "{{") ||
		strings.Contains(input.Data, "}}") {

		return nil
	}

	var payload []byte

	switch strings.ToLower(input.Type) {
	case "", "text":
		payload = []byte(input.Data)

	case "hex":
		decoded, err := hex.DecodeString(
			strings.TrimSpace(input.Data),
		)

		if err != nil {
			return nil
		}

		payload = decoded

	default:
		return nil
	}

	if len(payload) == 0 || len(payload) > 2048 {
		return nil
	}

	readSize := request.ReadSize

	if readSize == 0 {
		readSize = 1024
	}

	if readSize < 1 || readSize > 4096 {
		return nil
	}

	condition, ok := normalizeCondition(
		request.MatchersCondition,
	)

	if !ok {
		return nil
	}

	var matchers []Matcher

	for _, raw := range request.Matchers {
		matcher, ok := compileMatcher(raw)

		if !ok {
			return nil
		}

		matchers = append(matchers, matcher)
	}

	var transports []bool

	for _, host := range request.Host {
		switch host {
		case "{{Hostname}}", "{{Host}}":
			transports = appendUniqueBool(
				transports,
				false,
			)

		case "tls://{{Hostname}}", "tls://{{Host}}":
			transports = appendUniqueBool(
				transports,
				true,
			)
		}
	}

	if len(transports) == 0 {
		return nil
	}

	ports := parseRequestPorts(request.Port)

	probes := make(
		[]Probe,
		0,
		len(transports),
	)

	for _, secure := range transports {
		probes = append(
			probes,
			Probe{
				ID:        tmpl.ID,
				Service:   service,
				TLS:       secure,
				Payload:   payload,
				ReadSize:  readSize,
				Ports:     ports,
				Matchers:  matchers,
				Condition: condition,
			},
		)
	}

	return probes
}
