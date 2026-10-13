package analyzer

import (
	"bytes"
	"fmt"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
)

func MatchRequest(
	probe requests.Probe,
	response []byte,
) models.FingerprintMatch {
	if len(response) == 0 ||
		len(probe.Matchers) == 0 {

		return models.FingerprintMatch{}
	}

	matched := probe.Condition == "and"

	for _, rule := range probe.Matchers {
		ok := matchRequestRule(
			rule,
			response,
		)

		if probe.Condition == "and" {
			matched = matched && ok
		} else {
			matched = matched || ok
		}
	}

	if !matched {
		return models.FingerprintMatch{}
	}

	return models.FingerprintMatch{
		Service:    probe.Service,
		Confidence: "medium",
		Evidence: fmt.Sprintf(
			"Network detection template %q matched the response",
			probe.ID,
		),
	}
}

func matchRequestRule(
	rule requests.Matcher,
	response []byte,
) bool {
	total := len(rule.Words) + len(rule.Regexes)

	if total == 0 {
		return false
	}

	matched := rule.Condition == "and"

	for _, word := range rule.Words {
		ok := bytes.Contains(
			response,
			word,
		)

		if rule.CaseInsensitive {
			ok = bytes.Contains(
				bytes.ToLower(response),
				bytes.ToLower(word),
			)
		}

		if rule.Condition == "and" {
			matched = matched && ok
		} else {
			matched = matched || ok
		}
	}

	for _, regex := range rule.Regexes {
		ok := regex.Match(response)

		if rule.Condition == "and" {
			matched = matched && ok
		} else {
			matched = matched || ok
		}
	}

	return matched
}
