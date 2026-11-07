// Package detector counts rule hits per (rule, IP) in a sliding
// window and emits one detection per threshold crossing.
//
// Behaviour, by design: when the count inside the window reaches the
// rule's threshold, a detection is emitted and the counter for that
// (rule, IP) resets to zero, so a continuing attack fires again only
// after another full threshold of hits inside a fresh window. A
// detection is therefore never emitted twice for the same hits, and
// a sustained attack keeps producing detections instead of going
// quiet after the first one. Nothing here blocks or bans anything;
// stage 4 consumes detections to decide on firewall actions.
package detector

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"logbanner/internal/parser"
	"logbanner/internal/rules"
)

// Detection is one threshold crossing.
type Detection struct {
	RuleName  string
	RuleID    string
	Source    string // log format the event came from (nginx, ssh, ...)
	IP        net.IP
	Count     int
	Window    time.Duration
	FirstSeen time.Time
	LastSeen  time.Time
	// Offence counts how many times this rule has fired for this IP
	// since the detector started, starting at 1.
	Offence  int
	Severity string // "warning", or "critical" for a single-hit rule or a repeat offence
	Sample   parser.Event
}

// Message is the human-readable one-line summary stored with the event.
func (d Detection) Message() string {
	unit := "events"
	if d.Count == 1 {
		unit = "event"
	}
	msg := fmt.Sprintf("%s: %d %s from %s in %s (offence %d)",
		d.RuleName, d.Count, unit, d.IP.String(), d.Window, d.Offence)
	if d.Sample.Method != "" || d.Sample.Path != "" {
		msg += fmt.Sprintf(", last: %s %s status %d", d.Sample.Method, d.Sample.Path, d.Sample.Status)
	} else if d.Sample.Message != "" {
		msg += fmt.Sprintf(", last: %s", d.Sample.Message)
	}
	return msg
}

type stateKey struct {
	rule string
	ip   string
}

type state struct {
	times     []time.Time
	offence   int
	lastEvent time.Time
}

// Detector evaluates loaded rules against parsed events.
type Detector struct {
	mu     sync.Mutex
	rules  atomic.Pointer[rules.Set]
	states map[stateKey]*state
	now    func() time.Time // injected in tests; defaults to time.Now

	fired atomic.Uint64
}

// New returns a Detector over the given rule set.
func New(set *rules.Set) *Detector {
	d := &Detector{states: map[stateKey]*state{}, now: time.Now}
	d.rules.Store(set)
	return d
}

// SetRules atomically swaps the active rule set. Events already being
// processed finish against the old set; the next event sees the new
// one. Counters for rules that no longer exist are dropped by the
// next Cleanup.
func (d *Detector) SetRules(set *rules.Set) {
	d.rules.Store(set)
}

// Rule returns the enabled rule with that name from the current rule
// set, or nil. Stage 4 uses it to find a detection's action and
// escalation without keeping a second copy of the rules.
func (d *Detector) Rule(name string) *rules.Rule {
	set := d.rules.Load()
	if set == nil {
		return nil
	}
	return set.ByName(name)
}

// Fired returns how many detections have been emitted.
func (d *Detector) Fired() uint64 { return d.fired.Load() }

// Process evaluates ev (from log format `format`) against every
// enabled rule for that format and returns any detections it
// produces, usually none or one.
func (d *Detector) Process(format string, ev parser.Event) []Detection {
	if ev.IP == nil {
		return nil
	}
	// The window is measured on the event's own timestamp, so a
	// replayed or backfilled log behaves the same as a live one. A
	// zero timestamp (formats that carry none) falls back to now.
	at := ev.OccurredAt
	if at.IsZero() {
		at = d.now()
	}

	set := d.rules.Load()
	if set == nil {
		return nil
	}
	var out []Detection
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range set.Rules() {
		if r.Source != format || !r.Matches(ev) {
			continue
		}
		key := stateKey{rule: r.Name, ip: ev.IP.String()}
		st, ok := d.states[key]
		if !ok {
			st = &state{}
			d.states[key] = st
		}
		window := time.Duration(r.WindowSeconds) * time.Second
		st.times = append(st.times, at)
		st.lastEvent = at
		// Drop hits that fell out of the window before counting.
		cutoff := at.Add(-window)
		kept := st.times[:0]
		for _, t := range st.times {
			if !t.Before(cutoff) {
				kept = append(kept, t)
			}
		}
		st.times = kept
		if len(st.times) < r.Threshold {
			continue
		}
		st.offence++
		severity := "warning"
		// A rule that fires on a single event only exists for signals
		// that are malicious on their own (a scanner user-agent), and
		// a repeat offence is an escalation either way.
		if r.Threshold == 1 || st.offence >= 2 {
			severity = "critical"
		}
		out = append(out, Detection{
			RuleName:  r.Name,
			RuleID:    r.ID,
			Source:    format,
			IP:        ev.IP,
			Count:     len(st.times),
			Window:    window,
			FirstSeen: st.times[0],
			LastSeen:  st.times[len(st.times)-1],
			Offence:   st.offence,
			Severity:  severity,
			Sample:    ev,
		})
		d.fired.Add(1)
		// Reset the counter so this detection is emitted once per
		// threshold of hits; the offence count is kept.
		st.times = nil
	}
	return out
}

// Cleanup drops expired hits and state for rules that are gone or
// have been quiet for longer than their window. It is cheap enough
// to run once a minute from the agent's ticker.
func (d *Detector) Cleanup() {
	now := d.now()
	set := d.rules.Load()
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, st := range d.states {
		r := (*rules.Rule)(nil)
		if set != nil {
			r = set.ByName(key.rule)
		}
		if r == nil {
			delete(d.states, key)
			continue
		}
		window := time.Duration(r.WindowSeconds) * time.Second
		cutoff := now.Add(-window)
		kept := st.times[:0]
		for _, t := range st.times {
			if !t.Before(cutoff) {
				kept = append(kept, t)
			}
		}
		st.times = kept
		if len(st.times) == 0 && now.Sub(st.lastEvent) > window {
			delete(d.states, key)
		}
	}
}
