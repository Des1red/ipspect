package requests

import "regexp"

type Matcher struct {
	Condition       string
	Words           [][]byte
	Regexes         []*regexp.Regexp
	CaseInsensitive bool
	Negative        bool
}

type Exchange struct {
	Payload  []byte
	ReadSize int
}

type Probe struct {
	ID        string
	Service   string
	TLS       bool
	Payload   []byte
	ReadSize  int
	Exchanges []Exchange
	Ports     []int
	Matchers  []Matcher
	Condition string
}

type requestTemplate struct {
	ID      string         `yaml:"id"`
	Info    map[string]any `yaml:"info"`
	TCP     []templateTCP  `yaml:"tcp"`
	Network []templateTCP  `yaml:"network"`
}

type templateTCP struct {
	Host              []string            `yaml:"host"`
	Port              string              `yaml:"port"`
	Inputs            []templateInput     `yaml:"inputs"`
	ReadSize          int                 `yaml:"read-size"`
	ReadAll           bool                `yaml:"read-all"`
	Matchers          []templateMatcher   `yaml:"matchers"`
	MatchersCondition string              `yaml:"matchers-condition"`
	StopAtFirstMatch  bool                `yaml:"stop-at-first-match"`
	Extractors        []templateExtractor `yaml:"extractors"`
}

type templateInput struct {
	Data string `yaml:"data"`
	Type string `yaml:"type"`
	Read int    `yaml:"read"`
}

type templateMatcher struct {
	Type            string   `yaml:"type"`
	Name            string   `yaml:"name"`
	Part            string   `yaml:"part"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Condition       string   `yaml:"condition"`
	DSL             []string `yaml:"dsl"`
	Encoding        string   `yaml:"encoding"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	MatchAll        bool     `yaml:"match-all"`
	Negative        bool     `yaml:"negative"`
}

type templateExtractor struct {
	Type  string   `yaml:"type"`
	Name  string   `yaml:"name"`
	Part  string   `yaml:"part"`
	Regex []string `yaml:"regex"`
	Group int      `yaml:"group"`
	Kval  []string `yaml:"kval"`
}
