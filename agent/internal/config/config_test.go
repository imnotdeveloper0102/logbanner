package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DryRun {
		t.Error("dry_run should default to true")
	}
	if cfg.RulesPath != "rules/defaults.yaml" {
		t.Errorf("rules_path = %q", cfg.RulesPath)
	}
}

func TestLoadFileAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	body := "dry_run: false\nrules_path: /etc/logbanner/rules.yaml\nsources:\n  - path: /var/log/nginx/access.log\n    format: nginx\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/logbanner")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DryRun {
		t.Error("dry_run should be false from file")
	}
	if cfg.RulesPath != "/etc/logbanner/rules.yaml" {
		t.Errorf("rules_path = %q", cfg.RulesPath)
	}
	if cfg.DatabaseURL != "postgres://u:p@localhost:5432/logbanner" {
		t.Errorf("database_url = %q", cfg.DatabaseURL)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].Format != "nginx" {
		t.Errorf("sources = %+v", cfg.Sources)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("dry_run: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected an error for invalid YAML")
	}
}

func TestLoadCustomFormats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	body := "state_dir: /var/lib/logbanner\n" +
		"formats:\n" +
		"  - name: app\n" +
		"    regex: '^(?P<ip>\\S+) (?P<message>.*)$'\n" +
		"    time_format: \"2006-01-02T15:04:05Z07:00\"\n" +
		"sources:\n" +
		"  - path: /var/log/app.log\n" +
		"    format: app\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StateDir != "/var/lib/logbanner" {
		t.Errorf("state_dir = %q", cfg.StateDir)
	}
	if len(cfg.Formats) != 1 || cfg.Formats[0].Name != "app" {
		t.Errorf("formats = %+v", cfg.Formats)
	}
}

func TestLoadRejectsUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	body := "sources:\n  - path: /var/log/x.log\n    format: nope\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected an error for an unknown source format")
	}
}

func TestLoadRejectsBadCustomFormat(t *testing.T) {
	cases := []string{
		// Invalid regex.
		"formats:\n  - name: app\n    regex: '['\n",
		// Unknown named group.
		"formats:\n  - name: app\n    regex: '^(?P<nope>.*)$'\n",
		// Name collides with a built-in format.
		"formats:\n  - name: nginx\n    regex: '^(?P<ip>.*)$'\n",
		// Duplicate name.
		"formats:\n  - name: app\n    regex: '^(?P<ip>.*)$'\n  - name: app\n    regex: '^(?P<ip>.*)$'\n",
	}
	for i, body := range cases {
		path := filepath.Join(t.TempDir(), "agent.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestLoadWhitelistDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Whitelist) != 3 {
		t.Fatalf("default whitelist = %v, want the 3 RFC1918 ranges", cfg.Whitelist)
	}
	if cfg.FirewallDriver != "nftables" {
		t.Errorf("firewall_driver default = %q, want nftables", cfg.FirewallDriver)
	}
}

func TestLoadWhitelistExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	body := "whitelist:\n  - 203.0.113.10\n  - 2001:db8::/32\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Whitelist) != 2 || cfg.Whitelist[0] != "203.0.113.10" {
		t.Errorf("whitelist = %v", cfg.Whitelist)
	}
}

func TestLoadWhitelistEmptyListDisablesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("whitelist: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Whitelist) != 0 {
		t.Errorf("explicit empty whitelist = %v, want no ranges", cfg.Whitelist)
	}
}

func TestLoadRejectsBadWhitelistAndDriver(t *testing.T) {
	cases := []string{
		"whitelist:\n  - not-a-cidr\n",
		"whitelist:\n  - 10.0.0.0/33\n",
		"firewall_driver: pf\n",
	}
	for i, body := range cases {
		path := filepath.Join(t.TempDir(), "agent.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestLoadFirewallDriverEnv(t *testing.T) {
	t.Setenv("AGENT_FIREWALL_DRIVER", "iptables")
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FirewallDriver != "iptables" {
		t.Errorf("firewall_driver from env = %q, want iptables", cfg.FirewallDriver)
	}

	t.Setenv("AGENT_FIREWALL_DRIVER", "pf")
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected an error for an unknown driver from env")
	}
}

func TestLoadStateDirDefaultAndEnv(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StateDir != "var" {
		t.Errorf("state_dir default = %q, want %q", cfg.StateDir, "var")
	}

	t.Setenv("AGENT_STATE_DIR", "/tmp/logbanner-state")
	cfg, err = Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StateDir != "/tmp/logbanner-state" {
		t.Errorf("state_dir from env = %q", cfg.StateDir)
	}
}

func TestLoadCircuitBreakerDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MaxActiveBans != 1000 {
		t.Errorf("max_active_bans = %d, want 1000", cfg.MaxActiveBans)
	}
	if cfg.CircuitBreaker.MaxBans != 20 || cfg.CircuitBreaker.WindowSeconds != 600 || cfg.CircuitBreaker.CooldownSeconds != 600 {
		t.Errorf("circuit_breaker = %+v, want {20 600 600}", cfg.CircuitBreaker)
	}
}

func TestLoadCircuitBreakerFromFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	body := "dry_run: true\nrules_path: r.yaml\nmax_active_bans: 50\ncircuit_breaker:\n  max_bans: 5\n  window_seconds: 120\n  cooldown_seconds: 300\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_MAX_ACTIVE_BANS", "77")
	t.Setenv("AGENT_CB_MAX_BANS", "9")
	t.Setenv("AGENT_CB_WINDOW_SECONDS", "60")
	t.Setenv("AGENT_CB_COOLDOWN_SECONDS", "30")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MaxActiveBans != 77 {
		t.Errorf("max_active_bans = %d, want 77 from env", cfg.MaxActiveBans)
	}
	if cfg.CircuitBreaker.MaxBans != 9 || cfg.CircuitBreaker.WindowSeconds != 60 || cfg.CircuitBreaker.CooldownSeconds != 30 {
		t.Errorf("circuit_breaker = %+v, want {9 60 30} from env", cfg.CircuitBreaker)
	}
}

func TestLoadRejectsBadBreakerAndMaxBans(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"max_active_bans: 0\n":                       "max_active_bans 0",
		"circuit_breaker:\n  max_bans: 0\n":          "max_bans 0",
		"circuit_breaker:\n  window_seconds: 0\n":    "window_seconds 0",
		"circuit_breaker:\n  cooldown_seconds: -5\n": "cooldown_seconds -5",
	} {
		path := filepath.Join(dir, "agent.yaml")
		full := "dry_run: true\nrules_path: r.yaml\n" + body
		if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load accepted %s, want an error", name)
		}
	}
}
