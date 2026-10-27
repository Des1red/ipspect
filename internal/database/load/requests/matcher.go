package requests

import (
	"encoding/hex"
	"regexp"
)

func compileMatcher(raw templateMatcher) (Matcher, bool) {
	if raw.Encoding != "" && raw.Encoding != "hex" {
		return Matcher{}, false
	}

	switch raw.Part {
	case "", "raw", "body", "data", "all":
	default:
		return Matcher{}, false
	}

	condition, ok := normalizeCondition(raw.Condition)
	if !ok {
		return Matcher{}, false
	}
	if raw.MatchAll {
		condition = "and"
	}

	matcher := Matcher{
		Condition:       condition,
		CaseInsensitive: raw.CaseInsensitive,
		Negative:        raw.Negative,
	}

	switch raw.Type {
	case "word", "binary":
		if len(raw.Words) == 0 || len(raw.Words) > 64 {
			return Matcher{}, false
		}

		for _, word := range raw.Words {
			var data []byte

			if raw.Type == "binary" || raw.Encoding == "hex" {
				decoded, err := hex.DecodeString(word)
				if err != nil {
					return Matcher{}, false
				}
				data = decoded
			} else {
				data = []byte(word)
			}

			if len(data) == 0 {
				return Matcher{}, false
			}

			matcher.Words = append(matcher.Words, data)
		}

	case "regex":
		if len(raw.Regex) == 0 || len(raw.Regex) > 32 {
			return Matcher{}, false
		}

		for _, pattern := range raw.Regex {
			if len(pattern) > 1024 {
				return Matcher{}, false
			}

			if raw.CaseInsensitive {
				pattern = "(?i)" + pattern
			}

			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return Matcher{}, false
			}

			matcher.Regexes = append(matcher.Regexes, compiled)
		}

	default:
		return Matcher{}, false
	}

	return matcher, true
}
