package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"logbanner/internal/config"
)

func mustParser(t *testing.T, format string, custom []config.CustomFormat) Parser {
	t.Helper()
	p, err := New(format, custom)
	if err != nil {
		t.Fatalf("New(%q): %v", format, err)
	}
	return p
}

func testdata(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	return lines
}

func TestCombinedParserNginx(t *testing.T) {
	p := mustParser(t, "nginx", nil)
	lines := testdata(t, "nginx-access.log")
	if len(lines) != 6 {
		t.Fatalf("expected 6 testdata lines, got %d", len(lines))
	}

	ev, err := p.Parse("/var/log/nginx/access.log", lines[0])
	if err != nil {
		t.Fatalf("Parse line 0: %v", err)
	}
	if ev.IP.String() != "203.0.113.7" {
		t.Errorf("IP = %v", ev.IP)
	}
	if ev.Method != "GET" || ev.Path != "/index.html" || ev.Status != 200 {
		t.Errorf("request = %s %s %d", ev.Method, ev.Path, ev.Status)
	}
	if ev.User != "" {
		t.Errorf("User = %q, want empty (dash in log)", ev.User)
	}
	if !strings.Contains(ev.UserAgent, "Mozilla/5.0") {
		t.Errorf("UserAgent = %q", ev.UserAgent)
	}
	wantTime := time.Date(2026, 11, 7, 10, 15, 32, 0, time.FixedZone("", 7*3600))
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, wantTime)
	}

	// Authenticated user, POST, redirect status.
	ev, err = p.Parse("/var/log/nginx/access.log", lines[1])
	if err != nil {
		t.Fatalf("Parse line 1: %v", err)
	}
	if ev.User != "alice" || ev.Method != "POST" || ev.Path != "/login" || ev.Status != 302 {
		t.Errorf("line 1 = user %q %s %s %d", ev.User, ev.Method, ev.Path, ev.Status)
	}

	// Probe for a sensitive path.
	ev, err = p.Parse("/var/log/nginx/access.log", lines[2])
	if err != nil {
		t.Fatalf("Parse line 2: %v", err)
	}
	if ev.Path != "/.env" || ev.Status != 404 || ev.IP.String() != "203.0.113.9" {
		t.Errorf("line 2 = %s %d from %v", ev.Path, ev.Status, ev.IP)
	}

	// IPv6 client address.
	ev, err = p.Parse("/var/log/nginx/access.log", lines[5])
	if err != nil {
		t.Fatalf("Parse line 5: %v", err)
	}
	if ev.IP.String() != "2001:db8::1" {
		t.Errorf("IP = %v", ev.IP)
	}
}

func TestCombinedParserApacheAlias(t *testing.T) {
	p := mustParser(t, "apache", nil)
	ev, err := p.Parse("/var/log/apache2/access.log", testdata(t, "nginx-access.log")[0])
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ev.Method != "GET" || ev.Status != 200 {
		t.Errorf("apache alias parsed as %s %d", ev.Method, ev.Status)
	}
}

func TestSSHParser(t *testing.T) {
	p := mustParser(t, "ssh", nil)
	lines := testdata(t, "auth.log")
	if len(lines) != 9 {
		t.Fatalf("expected 9 testdata lines, got %d", len(lines))
	}

	cases := []struct {
		line    int
		outcome string
		method  string
		user    string
		ip      string
	}{
		{0, "failed", "password", "admin", "203.0.113.5"},
		{1, "failed", "password", "root", "203.0.113.5"},
		{2, "failed", "publickey", "deploy", "198.51.100.44"},
		{3, "accepted", "publickey", "deploy", "198.51.100.44"},
		{4, "invalid_user", "", "test", "203.0.113.9"},
		{5, "closed", "", "root", "203.0.113.5"},
		{6, "accepted", "password", "alice", "203.0.113.12"},
		{7, "disconnected", "", "bob", "203.0.113.9"},
		{8, "closed", "", "", "198.51.100.44"},
	}
	for _, tc := range cases {
		ev, err := p.Parse("/var/log/auth.log", lines[tc.line])
		if err != nil {
			t.Errorf("Parse line %d: %v", tc.line, err)
			continue
		}
		if ev.Extra["outcome"] != tc.outcome {
			t.Errorf("line %d: outcome = %v, want %s", tc.line, ev.Extra["outcome"], tc.outcome)
		}
		if tc.method != "" && ev.Extra["auth_method"] != tc.method {
			t.Errorf("line %d: auth_method = %v, want %s", tc.line, ev.Extra["auth_method"], tc.method)
		}
		if ev.User != tc.user {
			t.Errorf("line %d: user = %q, want %q", tc.line, ev.User, tc.user)
		}
		if ev.IP.String() != tc.ip {
			t.Errorf("line %d: ip = %v, want %s", tc.line, ev.IP, tc.ip)
		}
		if ev.OccurredAt.Year() != time.Now().Year() {
			t.Errorf("line %d: year = %d, want current year", tc.line, ev.OccurredAt.Year())
		}
	}
}

func TestSSHParserUnknownMessageKeepsEvent(t *testing.T) {
	p := mustParser(t, "ssh", nil)
	ev, err := p.Parse("/var/log/auth.log", "Nov  7 10:20:00 host sshd[1300]: Server listening on port 22.")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ev.IP != nil {
		t.Errorf("IP = %v, want nil for a message without an address", ev.IP)
	}
	if !strings.Contains(ev.Message, "Server listening") {
		t.Errorf("Message = %q", ev.Message)
	}
}

func TestJSONParser(t *testing.T) {
	p := mustParser(t, "json", nil)
	lines := testdata(t, "json-app.log")
	if len(lines) != 4 {
		t.Fatalf("expected 4 testdata lines, got %d", len(lines))
	}

	ev, err := p.Parse("/var/log/app.log", lines[0])
	if err != nil {
		t.Fatalf("Parse line 0: %v", err)
	}
	if ev.IP.String() != "203.0.113.7" || ev.Method != "GET" || ev.Path != "/api/health" || ev.Status != 200 {
		t.Errorf("line 0 = %v %s %s %d", ev.IP, ev.Method, ev.Path, ev.Status)
	}
	if ev.User != "alice" || ev.UserAgent != "curl/8.5.0" || ev.Message != "request handled" {
		t.Errorf("line 0 = user %q ua %q msg %q", ev.User, ev.UserAgent, ev.Message)
	}
	wantTime := time.Date(2026, 11, 7, 10, 15, 32, 0, time.FixedZone("", 7*3600))
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, wantTime)
	}

	// Epoch timestamp and an unknown field kept in Extra.
	ev, err = p.Parse("/var/log/app.log", lines[2])
	if err != nil {
		t.Fatalf("Parse line 2: %v", err)
	}
	wantEpoch := time.Date(2026, 11, 7, 3, 15, 32, 0, time.UTC)
	if !ev.OccurredAt.Equal(wantEpoch) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, wantEpoch)
	}
	if ev.Extra["request_id"] != "req-01" {
		t.Errorf("Extra = %v", ev.Extra)
	}

	// Missing fields are tolerated.
	ev, err = p.Parse("/var/log/app.log", lines[3])
	if err != nil {
		t.Fatalf("Parse line 3: %v", err)
	}
	if ev.IP.String() != "203.0.113.7" || ev.Message != "worker started" {
		t.Errorf("line 3 = %v %q", ev.IP, ev.Message)
	}
	if !ev.OccurredAt.IsZero() {
		t.Errorf("OccurredAt = %v, want zero time when timestamp is missing", ev.OccurredAt)
	}
}

func TestCustomFormatParser(t *testing.T) {
	custom := []config.CustomFormat{{
		Name:       "app",
		Regex:      `^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) (?P<ip>\S+) (?P<method>\S+) (?P<path>\S+) (?P<status>\d{3}) (?P<message>.*)$`,
		TimeFormat: time.RFC3339,
	}}
	p := mustParser(t, "app", custom)
	ev, err := p.Parse("/var/log/app.log", "2026-11-07T03:15:32Z 203.0.113.7 POST /api/login 401 bad credentials")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ev.IP.String() != "203.0.113.7" || ev.Method != "POST" || ev.Path != "/api/login" || ev.Status != 401 {
		t.Errorf("event = %v %s %s %d", ev.IP, ev.Method, ev.Path, ev.Status)
	}
	if ev.Message != "bad credentials" {
		t.Errorf("Message = %q", ev.Message)
	}
	wantTime := time.Date(2026, 11, 7, 3, 15, 32, 0, time.UTC)
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, wantTime)
	}
}

func TestCustomFormatDefaultTimeLayout(t *testing.T) {
	custom := []config.CustomFormat{{
		Name:  "plain",
		Regex: `^(?P<ip>\S+) (?P<message>.*)$`,
	}}
	p := mustParser(t, "plain", custom)
	ev, err := p.Parse("/var/log/plain.log", "203.0.113.7 something happened")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if ev.IP.String() != "203.0.113.7" || ev.Message != "something happened" {
		t.Errorf("event = %v %q", ev.IP, ev.Message)
	}
}

func TestUnparsableLines(t *testing.T) {
	cases := []struct {
		format string
		line   string
	}{
		{"nginx", "this is not a log line"},
		{"nginx", ""},
		{"nginx", `203.0.113.7 - - [not a date] "GET / HTTP/1.1" 200 1 "-" "-"`},
		{"ssh", "not a syslog line at all"},
		{"ssh", "Nov  7 10:15:32 host cron[1]: unrelated daemon line"},
		{"json", "not json"},
		{"json", `{"ip": "not json`},
		{"json", `[1, 2, 3]`},
	}
	for _, tc := range cases {
		p := mustParser(t, tc.format, nil)
		if _, err := p.Parse("/var/log/x.log", tc.line); err == nil {
			t.Errorf("format %s: expected error for %q, got none", tc.format, tc.line)
		}
	}

	custom := []config.CustomFormat{{
		Name:  "app",
		Regex: `^(?P<ip>\S+) (?P<message>.*)$`,
	}}
	p := mustParser(t, "app", custom)
	if _, err := p.Parse("/var/log/app.log", "no-ip-here-but-no-space-either"); err == nil {
		t.Error("custom format: expected error for a non-matching line")
	}
}

func TestNewUnknownFormat(t *testing.T) {
	if _, err := New("nope", nil); err == nil {
		t.Error("expected error for unknown format")
	}
	if _, err := New("app", []config.CustomFormat{{Name: "app", Regex: "["}}); err == nil {
		t.Error("expected error for invalid custom regex")
	}
}

func TestMetrics(t *testing.T) {
	m := NewMetrics()
	m.RecordRead("a.log")
	m.RecordRead("a.log")
	m.RecordRead("b.log")
	m.RecordParsed("a.log")
	m.RecordUnparsable("a.log")
	m.RecordUnparsable("b.log")

	snap := m.Snapshot()
	if snap.LinesRead != 3 || snap.Parsed != 1 || snap.Unparsable != 2 {
		t.Errorf("totals = %+v", snap)
	}
	if snap.PerSource["a.log"].LinesRead != 2 || snap.PerSource["a.log"].Parsed != 1 || snap.PerSource["a.log"].Unparsable != 1 {
		t.Errorf("a.log = %+v", snap.PerSource["a.log"])
	}
	if snap.PerSource["b.log"].LinesRead != 1 || snap.PerSource["b.log"].Unparsable != 1 {
		t.Errorf("b.log = %+v", snap.PerSource["b.log"])
	}
}
