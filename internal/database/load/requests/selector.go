package requests

import (
	"bytes"
	"ipspect/internal/models"
	"ipspect/internal/service"
	"sort"
)

// ForEvidence prioritizes requests using existing
// findings without excluding nonstandard-port services.
func ForEvidence(search models.NucleiSearch) []Probe {
	type candidate struct {
		probe Probe
		score int
	}

	evidence := selectionEvidence(search)

	serviceHint := service.Normalize(
		search.DBLookup,
	)

	candidates := make(
		[]candidate,
		0,
		len(requestsDB),
	)

	for _, probe := range requestsDB {
		score := 0

		if matchesPort(probe, search.Port) {
			score += 10
		}

		if serviceHint != "" &&
			service.Normalize(probe.Service) == serviceHint {

			score += 40
		}

		// Use the template's existing response
		// rules as a selection hint, not proof.
		if len(evidence) > 0 &&
			MatchResponse(probe, evidence) {

			score += 100
		}

		candidates = append(
			candidates,
			candidate{
				probe: probe,
				score: score,
			},
		)
	}

	sort.SliceStable(
		candidates,
		func(i, j int) bool {
			return candidates[i].score >
				candidates[j].score
		},
	)

	probes := make(
		[]Probe,
		0,
		len(candidates),
	)

	for _, candidate := range candidates {
		probes = append(
			probes,
			candidate.probe,
		)
	}

	return probes
}

func selectionEvidence(
	search models.NucleiSearch,
) []byte {
	var buffer bytes.Buffer

	buffer.Write(search.RawResponse)

	if search.Banner != "" {
		buffer.WriteByte('\n')
		buffer.WriteString(search.Banner)
	}

	// Keep header ordering deterministic.
	keys := make(
		[]string,
		0,
		len(search.Headers),
	)

	for key := range search.Headers {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		for _, value := range search.Headers[key] {
			buffer.WriteByte('\n')
			buffer.WriteString(key)
			buffer.WriteString(": ")
			buffer.WriteString(value)
		}
	}

	return buffer.Bytes()
}
