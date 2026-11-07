// Package rules loads detection rules from a YAML file and decides
// whether a parsed log event matches a rule.
//
// Pattern semantics (one pattern string, interpreted by prefix):
//
//	"*"            matches every event of the rule's source (e.g. http-flood)
//	"status=404"   matches an event whose HTTP status is exactly 404;
//	               "status=4xx" matches any 4xx status
//	"ua:<regex>"   matches the regex against the event's User-Agent
//	"<regex>"      otherwise the regex is matched, unanchored, against
//	               "METHOD PATH" for HTTP sources, and against the raw
//	               log line for the ssh source (the ssh parser normalises
//	               Message to an outcome word, so the raw line is the
//	               only place "Failed password" still appears)
//
// A rule applies only to events whose log format equals the rule's
// source (nginx, apache, ssh, ...), so an nginx rule never fires on
// Apache logs; copy the rule with source "apache" if both are wanted.
package rules

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"logbanner/internal/parser"
)

// MatchKind says how a rule's pattern is interpreted.
type MatchKind int

const (
	// KindMethodPath matches the pattern against "METHOD PATH".
	KindMethodPath MatchKind = iota
	// KindAll matches every event of the rule's source.
	KindAll
	// KindStatus matches on the HTTP status code.
	KindStatus
	// KindUserAgent matches the pattern against the User-Agent.
	KindUserAgent
	// KindRaw matches the pattern against the raw log line.
	KindRaw
)

// Meta is the per-rule state that lives in the database: the row id
// the events table references, and whether an admin has disabled it.
type Meta struct {
	ID      string
	Enabled bool
}

// Rule is one validated detection rule, ready to match events.
type Rule struct {
	Name          string
	Source        string
	Pattern       string
	Threshold     int
	WindowSeconds int
	BanSeconds    int
	Action        string
	// Escalation holds the ban length in seconds for offence 2, 3,
	// ...; a nil element means a permanent ban from that offence on.
	Escalation []*int

	// ID and Enabled come from the rules table via ApplyMeta; ID is
	// empty until the rule has been synced to the database.
	ID      string
	Enabled bool

	kind        MatchKind
	re          *regexp.Regexp
	status      int // exact status for KindStatus, -1 when unused
	statusClass int // status class (4 for 4xx) for KindStatus, -1 when unused
}

// fileRule is the YAML shape of one rule.
type fileRule struct {
	Name          string `yaml:"name"`
	Source        string `yaml:"source"`
	Pattern       string `yaml:"pattern"`
	Threshold     int    `yaml:"threshold"`
	WindowSeconds int    `yaml:"window_seconds"`
	BanSeconds    int    `yaml:"ban_seconds"`
	Action        string `yaml:"action"`
	Escalation    []*int `yaml:"escalation"`
}

type fileRules struct {
	Rules []fileRule `yaml:"rules"`
}

// Load reads, validates and compiles the rules in path.
func Load(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules %s: %w", path, err)
	}
	var file fileRules
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	if len(file.Rules) == 0 {
		return nil, fmt.Errorf("rules %s: no rules defined", path)
	}
	seen := make(map[string]bool, len(file.Rules))
	rules := make([]Rule, 0, len(file.Rules))
	for i, fr := range file.Rules {
		r, err := compile(fr)
		if err != nil {
			return nil, fmt.Errorf("rules %s: rule %d: %w", path, i, err)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("rules %s: duplicate rule name %q", path, r.Name)
		}
		seen[r.Name] = true
		r.Enabled = true
		rules = append(rules, r)
	}
	return rules, nil
}

// CompileFields validates and compiles a rule from its stored
// fields, for rules loaded from the database. The database is the
// source of truth from stage 6, so a rule edited in the UI must
// compile here exactly as a YAML rule would; a row that fails to
// compile is an error, not a silently skipped rule.
func CompileFields(name, source, pattern string, threshold, windowSeconds, banSeconds int, action string, escalation []*int) (Rule, error) {
	return compile(fileRule{
		Name:          name,
		Source:        source,
		Pattern:       pattern,
		Threshold:     threshold,
		WindowSeconds: windowSeconds,
		BanSeconds:    banSeconds,
		Action:        action,
		Escalation:    escalation,
	})
}

// compile validates one rule and compiles its pattern.
func compile(fr fileRule) (Rule, error) {
	r := Rule{
		Name:          fr.Name,
		Source:        fr.Source,
		Pattern:       fr.Pattern,
		Threshold:     fr.Threshold,
		WindowSeconds: fr.WindowSeconds,
		BanSeconds:    fr.BanSeconds,
		Action:        fr.Action,
		Escalation:    fr.Escalation,
		status:        -1,
		statusClass:   -1,
	}
	if r.Name == "" {
		return r, fmt.Errorf("rule needs a name")
	}
	if r.Source == "" {
		return r, fmt.Errorf("rule %q: source must not be empty", r.Name)
	}
	if r.Pattern == "" {
		return r, fmt.Errorf("rule %q: pattern must not be empty", r.Name)
	}
	if r.Threshold <= 0 {
		return r, fmt.Errorf("rule %q: threshold must be > 0, got %d", r.Name, r.Threshold)
	}
	if r.WindowSeconds <= 0 {
		return r, fmt.Errorf("rule %q: window_seconds must be > 0, got %d", r.Name, r.WindowSeconds)
	}
	if r.BanSeconds <= 0 {
		return r, fmt.Errorf("rule %q: ban_seconds must be > 0, got %d", r.Name, r.BanSeconds)
	}
	if r.Action != "ban" && r.Action != "log" {
		return r, fmt.Errorf("rule %q: action must be ban or log, got %q", r.Name, r.Action)
	}
	for i, step := range r.Escalation {
		if step != nil && *step <= 0 {
			return r, fmt.Errorf("rule %q: escalation step %d must be > 0", r.Name, i)
		}
	}

	switch {
	case r.Pattern == "*":
		r.kind = KindAll
	case strings.HasPrefix(r.Pattern, "status="):
		r.kind = KindStatus
		if err := r.parseStatus(strings.TrimPrefix(r.Pattern, "status=")); err != nil {
			return r, fmt.Errorf("rule %q: %w", r.Name, err)
		}
	case strings.HasPrefix(r.Pattern, "ua:"):
		r.kind = KindUserAgent
		re, err := regexp.Compile(strings.TrimPrefix(r.Pattern, "ua:"))
		if err != nil {
			return r, fmt.Errorf("rule %q: invalid user-agent pattern: %w", r.Name, err)
		}
		r.re = re
	case r.Source == "ssh":
		// The ssh parser reduces Message to an outcome word, so the
		// pattern is matched against the raw log line instead.
		r.kind = KindRaw
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return r, fmt.Errorf("rule %q: invalid pattern: %w", r.Name, err)
		}
		r.re = re
	default:
		r.kind = KindMethodPath
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return r, fmt.Errorf("rule %q: invalid pattern: %w", r.Name, err)
		}
		r.re = re
	}
	return r, nil
}

// parseStatus parses the part after "status=": a 3-digit code, or a
// class like "4xx".
func (r *Rule) parseStatus(s string) error {
	if len(s) == 3 && s[1:] == "xx" && s[0] >= '1' && s[0] <= '9' {
		r.statusClass = int(s[0] - '0')
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 100 || n > 999 {
		return fmt.Errorf("invalid status pattern %q: want status=NNN or status=Nxx", "status="+s)
	}
	r.status = n
	return nil
}

// BanDuration returns the ban length in seconds for the given
// offence number, or nil for a permanent ban. Offence 1 uses
// BanSeconds; offence 2 and up walk the escalation list, and an
// offence past the end of the list keeps the last step (so a
// trailing null stays permanent).
func (r *Rule) BanDuration(offence int) *int {
	if offence <= 1 || len(r.Escalation) == 0 {
		secs := r.BanSeconds
		return &secs
	}
	idx := offence - 2
	if idx >= len(r.Escalation) {
		idx = len(r.Escalation) - 1
	}
	return r.Escalation[idx]
}

// Matches reports whether ev counts as a hit for this rule. The
// caller checks the rule's source and enabled flag first; Matches
// only evaluates the pattern.
func (r *Rule) Matches(ev parser.Event) bool {
	switch r.kind {
	case KindAll:
		return true
	case KindStatus:
		if r.status >= 0 {
			return ev.Status == r.status
		}
		return ev.Status/100 == r.statusClass
	case KindUserAgent:
		return r.re.MatchString(ev.UserAgent)
	case KindRaw:
		return r.re.MatchString(ev.Raw)
	default: // KindMethodPath
		return r.re.MatchString(ev.Method + " " + ev.Path)
	}
}

// Set is an immutable snapshot of the active rules. The detector
// swaps it atomically on reload, so event processing never blocks
// on a reload and never sees a half-loaded rule set.
type Set struct {
	rules  []Rule
	byName map[string]*Rule
}

// NewSet builds a Set from loaded rules. Only enabled rules are kept:
// a rule an admin disabled in the database stays disabled across
// reloads, because SyncRules reports it as disabled and ApplyMeta
// marks it before the set is built.
func NewSet(rules []Rule) *Set {
	s := &Set{byName: make(map[string]*Rule, len(rules))}
	for i := range rules {
		if !rules[i].Enabled {
			continue
		}
		s.rules = append(s.rules, rules[i])
		s.byName[rules[i].Name] = &s.rules[len(s.rules)-1]
	}
	return s
}

// Rules returns the enabled rules in file order.
func (s *Set) Rules() []Rule { return s.rules }

// ByName returns the enabled rule with that name, or nil.
func (s *Set) ByName(name string) *Rule { return s.byName[name] }

// ApplyMeta attaches the database id and enabled flag from a sync to
// each loaded rule, matched by name. Rules with no row in meta keep
// their load-time values (enabled, no id); events for them are
// stored with a null rule_id until the next successful sync.
func ApplyMeta(rules []Rule, meta map[string]Meta) []Rule {
	for i := range rules {
		if m, ok := meta[rules[i].Name]; ok {
			rules[i].ID = m.ID
			rules[i].Enabled = m.Enabled
		}
	}
	return rules
}
