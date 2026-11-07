// Package config loads the agent configuration from a YAML file,
// with environment variables taking precedence for secrets and paths.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"

	"logbanner/internal/whitelist"
)

// Source describes one log file the agent tails.
type Source struct {
	Path   string `yaml:"path"`
	Format string `yaml:"format"`
}

// CustomFormat describes one user-defined log format, parsed by a
// regex with named groups. Recognised group names are ip, method,
// path, status, user_agent, user, message, time and timestamp.
type CustomFormat struct {
	Name       string `yaml:"name"`
	Regex      string `yaml:"regex"`
	TimeFormat string `yaml:"time_format"`
}

// CircuitBreakerConfig bounds automatic bans: at most MaxBans
// auto-bans inside WindowSeconds trips the breaker, which then
// refuses further auto-bans until CooldownSeconds have passed,
// when it re-arms on its own. Manual bans by an admin are explicit
// and never touch the breaker.
type CircuitBreakerConfig struct {
	MaxBans         int `yaml:"max_bans"`
	WindowSeconds   int `yaml:"window_seconds"`
	CooldownSeconds int `yaml:"cooldown_seconds"`
}

// Config is the whole agent configuration. Stage 2 adds StateDir and
// Formats; the detector that consumes RulesPath lands in stage 3;
// stage 4 adds FirewallDriver and Whitelist; stage 8 adds
// MaxActiveBans and CircuitBreaker.
type Config struct {
	DryRun         bool           `yaml:"dry_run"`
	FirewallDriver string         `yaml:"firewall_driver"`
	Whitelist      []string       `yaml:"whitelist"`
	RulesPath      string         `yaml:"rules_path"`
	DatabaseURL    string         `yaml:"database_url"`
	RedisAddr      string         `yaml:"redis_addr"`
	StateDir       string         `yaml:"state_dir"`
	Sources        []Source       `yaml:"sources"`
	Formats        []CustomFormat `yaml:"formats"`
	// MaxActiveBans caps the number of bans in force at once. An
	// auto-ban past the cap is refused with a log line and an event;
	// a manual ban by an admin is explicit and is not capped.
	MaxActiveBans  int                  `yaml:"max_active_bans"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
}

// defaultWhitelist is used when the config file sets no whitelist:
// the RFC1918 private ranges. Loopback is whitelisted unconditionally
// by the whitelist package, so it is not listed here. Setting
// `whitelist: []` in the file means no extra ranges at all.
var defaultWhitelist = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// knownFormats are the built-in parser names. Anything else must
// match a name in Formats.
var knownFormats = map[string]bool{
	"nginx":  true,
	"apache": true,
	"ssh":    true,
	"json":   true,
}

// knownFormatGroups are the named regex groups a custom format may use.
var knownFormatGroups = map[string]bool{
	"ip":         true,
	"method":     true,
	"path":       true,
	"status":     true,
	"user_agent": true,
	"user":       true,
	"message":    true,
	"time":       true,
	"timestamp":  true,
}

func defaults() Config {
	return Config{
		DryRun:         true,
		FirewallDriver: "nftables",
		Whitelist:      append([]string(nil), defaultWhitelist...),
		RulesPath:      "rules/defaults.yaml",
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		RedisAddr:      "localhost:6379",
		StateDir:       "var",
		MaxActiveBans:  1000,
		CircuitBreaker: CircuitBreakerConfig{MaxBans: 20, WindowSeconds: 600, CooldownSeconds: 600},
	}
}

// Load reads path when it exists and applies environment overrides.
// A missing file is not an error: defaults plus environment are enough
// to start the stage 1 skeleton.
func Load(path string) (Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := applyEnv(defaults())
			if err := cfg.validate(); err != nil {
				return Config{}, err
			}
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.FirewallDriver == "" {
		cfg.FirewallDriver = "nftables"
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "var"
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return applyEnv(cfg), nil
}

func applyEnv(cfg Config) Config {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		cfg.RedisAddr = v
	}
	if v := os.Getenv("AGENT_STATE_DIR"); v != "" {
		cfg.StateDir = v
	}
	if v := os.Getenv("AGENT_DRY_RUN"); v == "false" {
		cfg.DryRun = false
	}
	if v := os.Getenv("AGENT_FIREWALL_DRIVER"); v != "" {
		cfg.FirewallDriver = v
	}
	if v, err := strconv.Atoi(os.Getenv("AGENT_MAX_ACTIVE_BANS")); err == nil {
		cfg.MaxActiveBans = v
	}
	if v, err := strconv.Atoi(os.Getenv("AGENT_CB_MAX_BANS")); err == nil {
		cfg.CircuitBreaker.MaxBans = v
	}
	if v, err := strconv.Atoi(os.Getenv("AGENT_CB_WINDOW_SECONDS")); err == nil {
		cfg.CircuitBreaker.WindowSeconds = v
	}
	if v, err := strconv.Atoi(os.Getenv("AGENT_CB_COOLDOWN_SECONDS")); err == nil {
		cfg.CircuitBreaker.CooldownSeconds = v
	}
	return cfg
}

func (c Config) validate() error {
	if c.FirewallDriver != "nftables" && c.FirewallDriver != "iptables" {
		return fmt.Errorf("firewall_driver must be nftables or iptables, got %q", c.FirewallDriver)
	}
	if c.MaxActiveBans <= 0 {
		return fmt.Errorf("max_active_bans must be > 0, got %d", c.MaxActiveBans)
	}
	if c.CircuitBreaker.MaxBans <= 0 {
		return fmt.Errorf("circuit_breaker.max_bans must be > 0, got %d", c.CircuitBreaker.MaxBans)
	}
	if c.CircuitBreaker.WindowSeconds <= 0 {
		return fmt.Errorf("circuit_breaker.window_seconds must be > 0, got %d", c.CircuitBreaker.WindowSeconds)
	}
	if c.CircuitBreaker.CooldownSeconds <= 0 {
		return fmt.Errorf("circuit_breaker.cooldown_seconds must be > 0, got %d", c.CircuitBreaker.CooldownSeconds)
	}
	// Rejects a bad CIDR or IP at load, so a typo fails startup
	// instead of silently whitelisting nothing.
	if _, err := whitelist.New(c.Whitelist); err != nil {
		return fmt.Errorf("invalid whitelist: %w", err)
	}
	if c.RulesPath == "" {
		return fmt.Errorf("rules_path must not be empty")
	}
	if c.StateDir == "" {
		return fmt.Errorf("state_dir must not be empty")
	}
	custom := make(map[string]bool, len(c.Formats))
	for _, f := range c.Formats {
		if f.Name == "" {
			return fmt.Errorf("custom format needs a name")
		}
		if custom[f.Name] {
			return fmt.Errorf("duplicate custom format %q", f.Name)
		}
		custom[f.Name] = true
		if knownFormats[f.Name] {
			return fmt.Errorf("custom format %q collides with a built-in format", f.Name)
		}
		if f.Regex == "" {
			return fmt.Errorf("custom format %q needs a regex", f.Name)
		}
		re, err := regexp.Compile(f.Regex)
		if err != nil {
			return fmt.Errorf("custom format %q: invalid regex: %w", f.Name, err)
		}
		for _, name := range re.SubexpNames() {
			if name != "" && !knownFormatGroups[name] {
				return fmt.Errorf("custom format %q: unknown named group %q", f.Name, name)
			}
		}
	}
	for _, s := range c.Sources {
		if s.Path == "" {
			return fmt.Errorf("every log source needs a path")
		}
		if s.Format == "" {
			return fmt.Errorf("log source %s needs a format", s.Path)
		}
		if !knownFormats[s.Format] && !custom[s.Format] {
			return fmt.Errorf("log source %s: unknown format %q", s.Path, s.Format)
		}
	}
	return nil
}
