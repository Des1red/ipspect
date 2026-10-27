package requests

import "bytes"

func MatchResponse(probe Probe, response []byte) bool {
	if len(response) == 0 || len(probe.Matchers) == 0 {
		return false
	}

	matched := probe.Condition == "and"

	for _, rule := range probe.Matchers {
		ok := matchResponseRule(rule, response)
		if rule.Negative {
			ok = !ok
		}

		if probe.Condition == "and" {
			matched = matched && ok
		} else {
			matched = matched || ok
		}
	}

	return matched
}

func matchResponseRule(rule Matcher, response []byte) bool {
	total := len(rule.Words) + len(rule.Regexes)
	if total == 0 {
		return false
	}

	matched := rule.Condition == "and"

	for _, word := range rule.Words {
		ok := bytes.Contains(response, word)

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
