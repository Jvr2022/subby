package signature

type Signature struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Service     string   `yaml:"service" json:"service"`
	Severity    string   `yaml:"severity" json:"severity"`
	Confidence  string   `yaml:"confidence" json:"confidence"`
	Description string   `yaml:"description" json:"description"`
	Takeover    bool     `yaml:"takeover" json:"takeover"`
	Requires    []string `yaml:"requires" json:"requires,omitempty"`
	Matchers    Matchers `yaml:"matchers" json:"matchers"`
	References  []string `yaml:"references" json:"references,omitempty"`
	Source      string   `yaml:"-" json:"source,omitempty"`
}

type Matchers struct {
	CNAME    TextMatcher `yaml:"cname" json:"cname,omitempty"`
	NS       TextMatcher `yaml:"ns" json:"ns,omitempty"`
	Dangling bool        `yaml:"dangling" json:"dangling,omitempty"`
	HTTP     HTTPMatcher `yaml:"http" json:"http,omitempty"`
}

type TextMatcher struct {
	Contains []string `yaml:"contains" json:"contains,omitempty"`
	Equals   []string `yaml:"equals" json:"equals,omitempty"`
	Prefix   []string `yaml:"prefix" json:"prefix,omitempty"`
	Suffix   []string `yaml:"suffix" json:"suffix,omitempty"`
	Regex    []string `yaml:"regex" json:"regex,omitempty"`
}

type HTTPMatcher struct {
	Status  []int           `yaml:"status" json:"status,omitempty"`
	Body    TextMatcher     `yaml:"body" json:"body,omitempty"`
	Title   TextMatcher     `yaml:"title" json:"title,omitempty"`
	Headers []HeaderMatcher `yaml:"headers" json:"headers,omitempty"`
}

type HeaderMatcher struct {
	Name     string   `yaml:"name" json:"name"`
	Contains []string `yaml:"contains" json:"contains,omitempty"`
	Equals   []string `yaml:"equals" json:"equals,omitempty"`
	Prefix   []string `yaml:"prefix" json:"prefix,omitempty"`
	Suffix   []string `yaml:"suffix" json:"suffix,omitempty"`
	Regex    []string `yaml:"regex" json:"regex,omitempty"`
}

type Surface struct {
	Target      string
	CNAMEs      []string
	Nameservers []string
	Addresses   []string
	Dangling    bool
	HTTP        []HTTPObservation
}

type HTTPObservation struct {
	URL        string
	StatusCode int
	Headers    map[string][]string
	Body       string
	Title      string
	Error      string
}

type Evidence struct {
	Source  string `json:"source"`
	Matcher string `json:"matcher"`
	Pattern string `json:"pattern,omitempty"`
	Value   string `json:"value,omitempty"`
}

type MatchResult struct {
	Matched  bool       `json:"matched"`
	Partial  bool       `json:"partial"`
	Groups   []string   `json:"groups,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
}
