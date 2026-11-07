package detector

import (
	"net"
	"os"
	"testing"
	"time"

	"logbanner/internal/parser"
	"logbanner/internal/rules"
)

func loadRules(t *testing.T, content string) *rules.Set {
	t.Helper()
	// Load via a temp file so the YAML parsing path is exercised.
	path := t.TempDir() + "/rules.yaml"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := rules.Load(path)
	if err != nil {
		t.Fatalf("rules.Load: %v", err)
	}
	return rules.NewSet(rs)
}

func ev(ip string, at time.Time) parser.Event {
	return parser.Event{OccurredAt: at, IP: net.ParseIP(ip), Method: "GET", Path: "/", Status: 200}
}

func TestThresholdCrossing(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: http-flood, source: nginx, pattern: '*', threshold: 3, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d := New(set)
	base := time.Now()
	for i := 0; i < 2; i++ {
		if got := d.Process("nginx", ev("203.0.113.7", base.Add(time.Duration(i)*time.Second))); len(got) != 0 {
			t.Fatalf("event %d produced a detection, want none", i)
		}
	}
	got := d.Process("nginx", ev("203.0.113.7", base.Add(2*time.Second)))
	if len(got) != 1 {
		t.Fatalf("got %d detections, want 1", len(got))
	}
	det := got[0]
	if det.RuleName != "http-flood" || det.Count != 3 || det.Offence != 1 || det.Severity != "warning" {
		t.Errorf("detection = %+v", det)
	}
	if !det.FirstSeen.Equal(base) || !det.LastSeen.Equal(base.Add(2*time.Second)) {
		t.Errorf("window = %v..%v, want %v..%v", det.FirstSeen, det.LastSeen, base, base.Add(2*time.Second))
	}
	if d.Fired() != 1 {
		t.Errorf("Fired() = %d, want 1", d.Fired())
	}
}

func TestResetAfterFiring(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: http-flood, source: nginx, pattern: '*', threshold: 2, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d := New(set)
	base := time.Now()
	d.Process("nginx", ev("203.0.113.7", base))
	if got := d.Process("nginx", ev("203.0.113.7", base.Add(time.Second))); len(got) != 1 {
		t.Fatalf("second event: got %d detections, want 1", len(got))
	}
	// The counter reset on firing: one more event must not fire again.
	if got := d.Process("nginx", ev("203.0.113.7", base.Add(2*time.Second))); len(got) != 0 {
		t.Fatalf("event after firing: got %d detections, want 0 (counter reset)", len(got))
	}
	// A second full threshold fires again, as offence 2, critical.
	got := d.Process("nginx", ev("203.0.113.7", base.Add(3*time.Second)))
	if len(got) != 1 {
		t.Fatalf("fourth event: got %d detections, want 1", len(got))
	}
	if got[0].Offence != 2 || got[0].Severity != "critical" {
		t.Errorf("second firing = offence %d severity %q, want 2 critical", got[0].Offence, got[0].Severity)
	}
}

func TestWindowExpiry(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: http-flood, source: nginx, pattern: '*', threshold: 3, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d := New(set)
	base := time.Now()
	d.Process("nginx", ev("203.0.113.7", base))
	d.Process("nginx", ev("203.0.113.7", base.Add(time.Second)))
	// Third hit arrives after the first two fell out of the window.
	if got := d.Process("nginx", ev("203.0.113.7", base.Add(61*time.Second))); len(got) != 0 {
		t.Fatalf("got %d detections, want 0: old hits must expire", len(got))
	}
	// Two more inside the new window complete a fresh threshold.
	d.Process("nginx", ev("203.0.113.7", base.Add(62*time.Second)))
	if got := d.Process("nginx", ev("203.0.113.7", base.Add(63*time.Second))); len(got) != 1 {
		t.Fatalf("got %d detections, want 1", len(got))
	}
}

func TestPerIPIsolation(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: http-flood, source: nginx, pattern: '*', threshold: 2, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d := New(set)
	base := time.Now()
	d.Process("nginx", ev("203.0.113.7", base))
	if got := d.Process("nginx", ev("198.51.100.23", base)); len(got) != 0 {
		t.Fatalf("hits from two IPs produced %d detections, want 0", len(got))
	}
	if got := d.Process("nginx", ev("203.0.113.7", base)); len(got) != 1 {
		t.Fatalf("got %d detections, want 1 for 203.0.113.7", len(got))
	}
}

func TestSourceMismatchIgnored(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: http-flood, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d := New(set)
	if got := d.Process("ssh", ev("203.0.113.7", time.Now())); len(got) != 0 {
		t.Fatalf("nginx rule fired on an ssh event: %v", got)
	}
}

func TestNilIPIgnored(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: http-flood, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d := New(set)
	if got := d.Process("nginx", parser.Event{OccurredAt: time.Now()}); len(got) != 0 {
		t.Fatalf("event without an IP produced %d detections, want 0", len(got))
	}
}

func TestBotSingleHitIsCritical(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: malicious-bot, source: nginx, pattern: 'ua:(?i)(sqlmap|nikto|nmap)', threshold: 1, window_seconds: 60, ban_seconds: 3600, action: ban}
`)
	d := New(set)
	got := d.Process("nginx", parser.Event{
		OccurredAt: time.Now(), IP: net.ParseIP("203.0.113.9"),
		Method: "GET", Path: "/", Status: 200, UserAgent: "sqlmap/1.7",
	})
	if len(got) != 1 {
		t.Fatalf("got %d detections, want 1", len(got))
	}
	if got[0].Severity != "critical" || got[0].Count != 1 {
		t.Errorf("bot detection = severity %q count %d, want critical 1", got[0].Severity, got[0].Count)
	}
	if got := d.Process("nginx", parser.Event{
		OccurredAt: time.Now(), IP: net.ParseIP("203.0.113.9"),
		Method: "GET", Path: "/", Status: 200, UserAgent: "Mozilla/5.0",
	}); len(got) != 0 {
		t.Fatalf("normal user-agent produced %d detections, want 0", len(got))
	}
}

func TestSSHBruteForce(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: ssh-brute-force, source: ssh, pattern: 'Failed password', threshold: 5, window_seconds: 300, ban_seconds: 3600, action: ban}
`)
	d := New(set)
	base := time.Now()
	for i := 0; i < 4; i++ {
		ev := parser.Event{
			OccurredAt: base.Add(time.Duration(i) * time.Second),
			IP:         net.ParseIP("203.0.113.5"),
			Message:    "failed",
			Raw:        "Nov  7 10:15:32 host sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2",
		}
		if got := d.Process("ssh", ev); len(got) != 0 {
			t.Fatalf("hit %d produced a detection, want none", i)
		}
	}
	ev := parser.Event{
		OccurredAt: base.Add(4 * time.Second),
		IP:         net.ParseIP("203.0.113.5"),
		Message:    "failed",
		Raw:        "Nov  7 10:15:36 host sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2",
	}
	if got := d.Process("ssh", ev); len(got) != 1 {
		t.Fatalf("5th hit: got %d detections, want 1", len(got))
	}
}

func TestCleanupDropsExpiredAndGoneRules(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: http-flood, source: nginx, pattern: '*', threshold: 100, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d := New(set)
	now := time.Now()
	d.now = func() time.Time { return now }
	d.Process("nginx", ev("203.0.113.7", now))
	if len(d.states) != 1 {
		t.Fatalf("states = %d, want 1", len(d.states))
	}
	// Still inside the window: state is kept.
	d.now = func() time.Time { return now.Add(30 * time.Second) }
	d.Cleanup()
	if len(d.states) != 1 {
		t.Fatalf("after cleanup inside window: states = %d, want 1", len(d.states))
	}
	// Past the window with no hits left: state is dropped.
	d.now = func() time.Time { return now.Add(61 * time.Second) }
	d.Cleanup()
	if len(d.states) != 0 {
		t.Fatalf("after cleanup past window: states = %d, want 0", len(d.states))
	}

	// State for a rule removed by a reload is dropped too.
	d.Process("nginx", ev("203.0.113.7", now.Add(62*time.Second)))
	empty := loadRules(t, `rules:
  - {name: other-rule, source: nginx, pattern: '*', threshold: 100, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d.SetRules(empty)
	d.Cleanup()
	if len(d.states) != 0 {
		t.Fatalf("after rule removal: states = %d, want 0", len(d.states))
	}
}

func TestSetRulesSwap(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: http-flood, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}
`)
	d := New(set)
	if got := d.Process("nginx", ev("203.0.113.7", time.Now())); len(got) != 1 {
		t.Fatalf("got %d detections, want 1", len(got))
	}
	// Swap in a set with the rule disabled (empty set): no more firing.
	d.SetRules(rules.NewSet(nil))
	if got := d.Process("nginx", ev("203.0.113.7", time.Now())); len(got) != 0 {
		t.Fatalf("after swap to empty set: got %d detections, want 0", len(got))
	}
}

// Stage 8: the offence number keeps counting across firings while
// the detector runs, so BanDuration walks the escalation steps
// (1 -> 60s, 2 -> 120s, 3 -> 300s, 4 -> permanent here). The
// counter itself is in-memory only: a restart, or Cleanup dropping
// a quiet (rule, IP), resets it to 1. That is why the agent
// derives the offence from the bans history in the database
// before banning (see store.OffenceCount and the agent main loop);
// this test pins the in-memory half of that contract.
func TestOffenceKeepsCountingAcrossFirings(t *testing.T) {
	set := loadRules(t, `rules:
  - {name: ssh-brute-force, source: ssh, pattern: 'Failed password', threshold: 1, window_seconds: 300, ban_seconds: 60, action: ban, escalation: [120, 300, null]}
`)
	d := New(set)
	base := time.Now()
	// Threshold 1 fires on every event; the rule still needs the
	// ssh raw line, so build the event with Raw set.
	sshEv := func(ip string, at time.Time) parser.Event {
		e := ev(ip, at)
		e.Raw = "Failed password for root from 203.0.113.5 port 22 ssh2"
		return e
	}
	for offence := 1; offence <= 4; offence++ {
		got := d.Process("ssh", sshEv("203.0.113.5", base.Add(time.Duration(offence)*time.Second)))
		if len(got) != 1 {
			t.Fatalf("firing %d: got %d detections, want 1", offence, len(got))
		}
		if got[0].Offence != offence {
			t.Errorf("firing %d: offence = %d, want %d", offence, got[0].Offence, offence)
		}
		duration := set.ByName("ssh-brute-force").BanDuration(got[0].Offence)
		switch offence {
		case 1:
			if duration == nil || *duration != 60 {
				t.Errorf("offence 1: duration = %v, want 60", duration)
			}
		case 2:
			if duration == nil || *duration != 120 {
				t.Errorf("offence 2: duration = %v, want 120", duration)
			}
		case 3:
			if duration == nil || *duration != 300 {
				t.Errorf("offence 3: duration = %v, want 300", duration)
			}
		case 4:
			if duration != nil {
				t.Errorf("offence 4: duration = %d, want permanent (nil)", *duration)
			}
		}
	}
}
