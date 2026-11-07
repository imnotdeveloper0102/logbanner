package rules

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"logbanner/internal/parser"
)

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const validYAML = `rules:
  - name: ssh-brute-force
    source: ssh
    pattern: "Failed password"
    threshold: 5
    window_seconds: 300
    ban_seconds: 3600
    action: ban
    escalation: [3600, 14400, 86400, null]
  - name: http-flood
    source: nginx
    pattern: "*"
    threshold: 300
    window_seconds: 60
    ban_seconds: 600
    action: ban
    escalation: [600, 3600, 86400, null]
`

func TestLoadValid(t *testing.T) {
	rs, err := Load(writeRules(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("got %d rules, want 2", len(rs))
	}
	ssh := rs[0]
	if ssh.Name != "ssh-brute-force" || ssh.Threshold != 5 || ssh.WindowSeconds != 300 {
		t.Errorf("ssh rule = %+v", ssh)
	}
	if len(ssh.Escalation) != 4 || ssh.Escalation[3] != nil {
		t.Errorf("escalation = %v, want [3600 14400 86400 null]", ssh.Escalation)
	}
	if ssh.Escalation[0] == nil || *ssh.Escalation[0] != 3600 {
		t.Errorf("escalation[0] = %v, want 3600", ssh.Escalation[0])
	}
	if !rs[0].Enabled || !rs[1].Enabled {
		t.Error("loaded rules should default to enabled")
	}
}

func TestLoadDefaultsFile(t *testing.T) {
	rs, err := Load("../../../rules/defaults.yaml")
	if err != nil {
		t.Fatalf("Load defaults.yaml: %v", err)
	}
	want := []string{"ssh-brute-force", "http-login-brute-force", "path-scanner", "http-404-scan", "http-flood", "malicious-bot"}
	if len(rs) != len(want) {
		t.Fatalf("got %d rules %v, want %d %v", len(rs), rs, len(want), want)
	}
	for i, name := range want {
		if rs[i].Name != name {
			t.Errorf("rule %d = %q, want %q", i, rs[i].Name, name)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"bad yaml":       "rules: [unclosed",
		"no rules":       "rules: []\n",
		"duplicate name": "rules:\n  - {name: a, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}\n  - {name: a, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}\n",
		"missing name":   "rules:\n  - {source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}\n",
		"missing source": "rules:\n  - {name: a, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}\n",
		"empty pattern":  "rules:\n  - {name: a, source: nginx, pattern: '', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}\n",
		"zero threshold": "rules:\n  - {name: a, source: nginx, pattern: '*', threshold: 0, window_seconds: 60, ban_seconds: 60, action: ban}\n",
		"zero window":    "rules:\n  - {name: a, source: nginx, pattern: '*', threshold: 1, window_seconds: 0, ban_seconds: 60, action: ban}\n",
		"zero ban":       "rules:\n  - {name: a, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 0, action: ban}\n",
		"bad action":     "rules:\n  - {name: a, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: drop}\n",
		"bad regex":      "rules:\n  - {name: a, source: nginx, pattern: '(unclosed', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}\n",
		"bad status":     "rules:\n  - {name: a, source: nginx, pattern: 'status=banana', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}\n",
		"bad ua regex":   "rules:\n  - {name: a, source: nginx, pattern: 'ua:(unclosed', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}\n",
		"bad escalation": "rules:\n  - {name: a, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban, escalation: [0]}\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeRules(t, content)); err == nil {
				t.Error("Load succeeded, want an error")
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("Load of a missing file succeeded, want an error")
	}
}

func mustRule(t *testing.T, yaml string) Rule {
	t.Helper()
	rs, err := Load(writeRules(t, "rules:\n"+yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return rs[0]
}

func TestMatches(t *testing.T) {
	now := time.Now()
	httpEv := parser.Event{
		OccurredAt: now, IP: net.ParseIP("203.0.113.7"),
		Method: "POST", Path: "/login", Status: 401,
		UserAgent: "Mozilla/5.0",
	}
	sshEv := parser.Event{
		OccurredAt: now, IP: net.ParseIP("203.0.113.5"),
		Message: "failed",
		Raw:     "Nov  7 10:15:32 host sshd[1234]: Failed password for root from 203.0.113.5 port 52341 ssh2",
	}
	cases := []struct {
		name  string
		yaml  string
		ev    parser.Event
		match bool
	}{
		{"method-path hit", `  - {name: a, source: nginx, pattern: 'POST /login', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, true},
		{"method-path miss on path", `  - {name: a, source: nginx, pattern: 'POST /logout', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, false},
		{"method-path miss on method", `  - {name: a, source: nginx, pattern: 'GET /login', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, false},
		{"match-all", `  - {name: a, source: nginx, pattern: '*', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, true},
		{"status exact hit", `  - {name: a, source: nginx, pattern: 'status=401', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, true},
		{"status exact miss", `  - {name: a, source: nginx, pattern: 'status=404', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, false},
		{"status class hit", `  - {name: a, source: nginx, pattern: 'status=4xx', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, true},
		{"status class miss", `  - {name: a, source: nginx, pattern: 'status=5xx', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, false},
		{"ua hit", `  - {name: a, source: nginx, pattern: 'ua:(?i)sqlmap', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, parser.Event{UserAgent: "sqlmap/1.7"}, true},
		{"ua miss", `  - {name: a, source: nginx, pattern: 'ua:(?i)sqlmap', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, httpEv, false},
		{"ssh raw hit", `  - {name: a, source: ssh, pattern: 'Failed password', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, sshEv, true},
		{"ssh raw miss on accepted", `  - {name: a, source: ssh, pattern: 'Failed password', threshold: 1, window_seconds: 60, ban_seconds: 60, action: ban}`, parser.Event{Message: "accepted", Raw: "Nov  7 10:16:02 host sshd[1237]: Accepted password for alice from 203.0.113.12 port 34567 ssh2"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mustRule(t, tc.yaml)
			if got := r.Matches(tc.ev); got != tc.match {
				t.Errorf("Matches = %v, want %v", got, tc.match)
			}
		})
	}
}

func TestNewSetSkipsDisabled(t *testing.T) {
	rs, err := Load(writeRules(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	rs[0].Enabled = false
	set := NewSet(rs)
	if len(set.Rules()) != 1 || set.Rules()[0].Name != "http-flood" {
		t.Errorf("Rules() = %v, want only http-flood", set.Rules())
	}
	if set.ByName("ssh-brute-force") != nil {
		t.Error("disabled rule should not be findable by name")
	}
	if set.ByName("http-flood") == nil {
		t.Error("enabled rule should be findable by name")
	}
}

func TestApplyMeta(t *testing.T) {
	rs, err := Load(writeRules(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	rs = ApplyMeta(rs, map[string]Meta{
		"ssh-brute-force": {ID: "11111111-1111-1111-1111-111111111111", Enabled: false},
	})
	if rs[0].ID != "11111111-1111-1111-1111-111111111111" || rs[0].Enabled {
		t.Errorf("ssh rule after ApplyMeta = id %q enabled %v", rs[0].ID, rs[0].Enabled)
	}
	if rs[1].ID != "" || !rs[1].Enabled {
		t.Errorf("http-flood after ApplyMeta = id %q enabled %v, want empty id and enabled", rs[1].ID, rs[1].Enabled)
	}
}
