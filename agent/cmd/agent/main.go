// Command agent is the logbanner detection agent.
//
// Stage 4 scope: on top of stage 3 detection, a detection whose
// rule says action=ban is checked against the whitelist, recorded
// in the bans table, applied to the firewall (nftables by default,
// iptables/ipset as fallback), and published on Redis. In dry-run
// (the default) the ban is recorded with dry_run=true and only
// logged as "would ban"; the firewall is never touched. Expired
// bans are unbanned by a background sweep, and active bans are
// re-applied to the firewall when the agent restarts.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"logbanner/internal/breaker"
	"logbanner/internal/config"
	"logbanner/internal/detector"
	"logbanner/internal/firewall"
	"logbanner/internal/parser"
	"logbanner/internal/rules"
	"logbanner/internal/store"
	"logbanner/internal/tailer"
	"logbanner/internal/whitelist"
)

// summaryInterval is how often the agent logs its parse counts.
const summaryInterval = 30 * time.Second

// cleanupInterval is how often the detector drops expired hits and
// state for rules that no longer exist.
const cleanupInterval = time.Minute

func main() {
	configPath := flag.String("config", "agent.yaml", "path to agent config file")
	debug := flag.Bool("debug", false, "enable debug logging (parsed events, unparsable lines)")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	loadedRules, err := rules.Load(cfg.RulesPath)
	if err != nil {
		logger.Error("failed to load rules", "path", cfg.RulesPath, "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The store is optional at runtime: without a database URL, or
	// when Postgres is unreachable, the agent still detects and logs,
	// it just stores nothing. A missing store is a warning, not a
	// fatal error, so a log-only deployment keeps working.
	var st *store.Store
	if cfg.DatabaseURL != "" {
		st, err = store.New(ctx, cfg.DatabaseURL, cfg.RedisAddr, logger)
		if err != nil {
			logger.Warn("storage unavailable, detections will only be logged", "error", err)
		}
	} else {
		logger.Warn("no database_url configured, detections will only be logged")
	}
	if st != nil {
		defer st.Close()
	}

	det := detector.New(rules.NewSet(loadActiveRules(ctx, st, loadedRules, logger)))

	// The whitelist is checked before every ban, with no exceptions.
	// It was already validated at config load; a failure here cannot
	// happen, but a ban path must never run without one.
	wl, err := whitelist.New(cfg.Whitelist)
	if err != nil {
		logger.Error("invalid whitelist", "error", err)
		os.Exit(1)
	}

	// In dry-run the driver only logs "would ban"; the firewall is
	// never touched and the binary is not even required. Live mode
	// builds the real driver, which fails loudly at startup when
	// its binary is missing or its table/sets cannot be created.
	var fw firewall.Driver
	if cfg.DryRun {
		fw = firewall.NewDryRun(logger)
	} else {
		fw, err = firewall.New(cfg.FirewallDriver)
		if err != nil {
			logger.Error("failed to initialise firewall driver", "driver", cfg.FirewallDriver, "error", err)
			os.Exit(1)
		}
	}
	bnr := &banner{
		store: st, driver: fw, wl: wl, log: logger, dryRun: cfg.DryRun,
		breaker:       breaker.New(cfg.CircuitBreaker.MaxBans, cfg.CircuitBreaker.WindowSeconds, cfg.CircuitBreaker.CooldownSeconds),
		maxActiveBans: cfg.MaxActiveBans,
	}

	// Restore bans recorded before the restart (and revoke ones that
	// expired while the agent was down) before tailing starts.
	bnr.restore(ctx)

	parsers := make(map[string]parser.Parser, len(cfg.Sources))
	formatByPath := make(map[string]string, len(cfg.Sources))
	for _, src := range cfg.Sources {
		p, err := parser.New(src.Format, cfg.Formats)
		if err != nil {
			logger.Error("unknown log format", "path", src.Path, "format", src.Format, "error", err)
			os.Exit(1)
		}
		parsers[src.Path] = p
		formatByPath[src.Path] = src.Format
	}

	metrics := parser.NewMetrics()
	startedAt := time.Now()

	// Snapshot the values the background goroutines need: cfg is
	// replaced on SIGHUP, and reading it from another goroutine
	// would race. Sources, state dir and Redis address only change
	// on a restart anyway.
	stateDir := cfg.StateDir
	tailSources := cfg.Sources
	redisAddr := cfg.RedisAddr

	// Manual ban/unban commands from the gateway arrive on
	// logbanner:commands; detection keeps running whether or not
	// Redis is up, so the listener retries on its own.
	go runCommandListener(ctx, redisAddr, bnr, logger)

	t, err := tailer.New(cfg.Sources, cfg.StateDir, logger)
	if err != nil {
		logger.Error("failed to create tailer", "error", err)
		os.Exit(1)
	}

	// SIGHUP re-reads the config file and the rules file, syncs the
	// rules to the database, and atomically swaps the detector's
	// active rule set. The tailer is not restarted: changing the
	// sources list still needs an agent restart.
	var cfgMu sync.Mutex
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reloaded, err := config.Load(*configPath)
			if err != nil {
				logger.Error("config reload failed, keeping previous config", "error", err)
				continue
			}
			reloadedRules, err := rules.Load(reloaded.RulesPath)
			if err != nil {
				logger.Error("rules reload failed, keeping previous rules", "path", reloaded.RulesPath, "error", err)
				continue
			}
			cfgMu.Lock()
			if reloaded.DryRun != cfg.DryRun || reloaded.FirewallDriver != cfg.FirewallDriver || !slices.Equal(reloaded.Whitelist, cfg.Whitelist) {
				logger.Warn("firewall settings changed (dry_run, firewall_driver or whitelist), restart the agent to apply them")
			}
			if reloaded.MaxActiveBans != cfg.MaxActiveBans || reloaded.CircuitBreaker != cfg.CircuitBreaker {
				logger.Warn("circuit breaker or max active bans changed, restart the agent to apply them")
			}
			cfg = reloaded
			cfgMu.Unlock()
			det.SetRules(rules.NewSet(loadActiveRules(ctx, st, reloadedRules, logger)))
			logger.Info("config and rules reloaded", "dry_run", reloaded.DryRun, "rules", len(reloadedRules), "sources", len(reloaded.Sources))
		}
	}()

	logger.Info("logbanner agent started",
		"dry_run", cfg.DryRun,
		"firewall_driver", fw.Name(),
		"whitelist_entries", len(cfg.Whitelist),
		"rules_path", cfg.RulesPath,
		"rules", len(loadedRules),
		"state_dir", cfg.StateDir,
		"sources", len(cfg.Sources),
		"max_active_bans", cfg.MaxActiveBans,
		"circuit_breaker_max_bans", cfg.CircuitBreaker.MaxBans,
		"circuit_breaker_window_seconds", cfg.CircuitBreaker.WindowSeconds,
		"circuit_breaker_cooldown_seconds", cfg.CircuitBreaker.CooldownSeconds,
		"storage", st != nil)

	t.Start(ctx)

	consumed := make(chan struct{})
	go func() {
		defer close(consumed)
		for line := range t.Lines() {
			metrics.RecordRead(line.Source)
			ev, err := parsers[line.Source].Parse(line.Source, line.Text)
			if err != nil {
				metrics.RecordUnparsable(line.Source)
				logger.Debug("unparsable line", "source", line.Source, "error", err)
				continue
			}
			metrics.RecordParsed(line.Source)
			logger.Debug("parsed event",
				"source", ev.Source,
				"ip", ev.IP.String(),
				"method", ev.Method,
				"path", ev.Path,
				"status", ev.Status,
				"user", ev.User,
				"message", ev.Message)
			for _, detection := range det.Process(formatByPath[line.Source], ev) {
				// Escalation survives a restart: the offence number
				// comes from the bans history in the database, not
				// only from the detector's in-memory counter, which
				// resets on restart and when a quiet (rule, IP) is
				// cleaned up. The larger of the two wins, so a ban
				// history deleted by hand cannot lower an offence
				// the detector already counted in this run. The
				// severity is re-derived with it, so a repeat
				// offence is critical even after a restart.
				if st != nil {
					if r := det.Rule(detection.RuleName); r != nil && r.Action == "ban" {
						if n, err := st.OffenceCount(ctx, detection.IP, detection.RuleID, detection.RuleName); err != nil {
							logger.Warn("offence count lookup failed, using in-memory offence", "rule", detection.RuleName, "ip", detection.IP.String(), "error", err)
						} else if n+1 > detection.Offence {
							detection.Offence = n + 1
							if detection.Offence >= 2 {
								detection.Severity = "critical"
							}
						}
					}
				}
				logger.Info("detection",
					"rule", detection.RuleName,
					"ip", detection.IP.String(),
					"count", detection.Count,
					"window", detection.Window.String(),
					"offence", detection.Offence,
					"severity", detection.Severity)
				if st == nil {
					continue
				}
				if err := st.SaveDetection(ctx, detection); err != nil {
					logger.Error("failed to store detection", "rule", detection.RuleName, "ip", detection.IP.String(), "error", err)
				}
				// Only a rule that says action=ban bans anything; a
				// "log" rule only ever records the detection above.
				if r := det.Rule(detection.RuleName); r != nil && r.Action == "ban" {
					bnr.handleBan(ctx, detection, r)
				}
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(summaryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				snap := metrics.Snapshot()
				// The gateway reads this file for the log-sources
				// page; a failed write is logged, never fatal.
				writeSourceStatus(stateDir, tailSources, snap, startedAt, logger)
				breakerOpen, _, breakerInWindow := bnr.breaker.State(time.Now())
				args := []any{
					"lines_read", snap.LinesRead,
					"parsed", snap.Parsed,
					"unparsable", snap.Unparsable,
					"detections", det.Fired(),
					"bans", bnr.bans.Load(),
					"bans_skipped_whitelist", bnr.skipped.Load(),
					"bans_refused", bnr.refused.Load(),
					"breaker_open", breakerOpen,
					"breaker_bans_in_window", breakerInWindow,
				}
				if st != nil {
					args = append(args, "events_stored", st.Stored(), "publish_failures", st.PublishFailures())
				}
				logger.Info("agent summary", args...)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				det.Cleanup()
				// Same cadence as the detector cleanup: unbanning a
				// few seconds late is harmless, and a second ticker
				// buys nothing.
				bnr.expireSweep(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
	t.Close()
	<-consumed
	snap := metrics.Snapshot()
	args := []any{
		"lines_read", snap.LinesRead,
		"parsed", snap.Parsed,
		"unparsable", snap.Unparsable,
		"detections", det.Fired(),
		"bans", bnr.bans.Load(),
		"bans_skipped_whitelist", bnr.skipped.Load(),
		"bans_refused", bnr.refused.Load(),
	}
	if st != nil {
		args = append(args, "events_stored", st.Stored(), "publish_failures", st.PublishFailures())
	}
	logger.Info("logbanner agent stopped", args...)
}

// loadActiveRules returns the rules the detector should run.
// With a store, the YAML file only seeds rules that do not exist
// yet (SyncRules inserts, never overwrites), and the active set is
// read back from the database — the single source of truth from
// stage 6, so a gateway edit survives the next SIGHUP. Without a
// store the file rules are used as-is, and a sync failure falls
// back to the file rules with their database meta attached.
func loadActiveRules(ctx context.Context, st *store.Store, loaded []rules.Rule, logger *slog.Logger) []rules.Rule {
	if st == nil {
		return loaded
	}
	meta, err := st.SyncRules(ctx, loaded)
	if err != nil {
		logger.Error("failed to sync rules to database, detections will have no rule_id", "error", err)
		return loaded
	}
	dbRules, err := st.LoadRules(ctx)
	if err != nil {
		logger.Error("failed to load rules from database, using file rules", "error", err)
		return rules.ApplyMeta(loaded, meta)
	}
	return dbRules
}

// sourceStatus is one entry of the status file the gateway reads
// for the log-sources page.
type sourceStatus struct {
	Path       string `json:"path"`
	Format     string `json:"format"`
	LinesRead  uint64 `json:"lines_read"`
	Parsed     uint64 `json:"parsed"`
	Unparsable uint64 `json:"unparsable"`
}

// writeSourceStatus writes the agent's per-source parse counts to
// <stateDir>/sources-status.json, atomically (temp file + rename),
// so the gateway never reads a half-written file. A failure is
// logged and ignored: the gateway reports "unavailable" instead.
func writeSourceStatus(stateDir string, sources []config.Source, snap parser.Snapshot, startedAt time.Time, logger *slog.Logger) {
	entries := make([]sourceStatus, 0, len(sources))
	for _, src := range sources {
		m := snap.PerSource[src.Path]
		entries = append(entries, sourceStatus{
			Path: src.Path, Format: src.Format,
			LinesRead: m.LinesRead, Parsed: m.Parsed, Unparsable: m.Unparsable,
		})
	}
	payload, err := json.Marshal(map[string]any{
		"agent_started_at": startedAt,
		"updated_at":       time.Now(),
		"sources":          entries,
	})
	if err != nil {
		logger.Error("failed to marshal source status", "error", err)
		return
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		logger.Error("failed to create state dir for source status", "dir", stateDir, "error", err)
		return
	}
	tmp := filepath.Join(stateDir, "sources-status.json.tmp")
	final := filepath.Join(stateDir, "sources-status.json")
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		logger.Error("failed to write source status", "error", err)
		return
	}
	if err := os.Rename(tmp, final); err != nil {
		logger.Error("failed to publish source status", "error", err)
	}
}

// banner turns a detection whose rule says action=ban into a
// firewall ban. The order is deliberate: the bans row is written
// first, then the firewall is touched, then the ban is published.
// If the firewall call fails, the row is already there, so the next
// restart restores the ban instead of losing it. In dry-run the row
// is still written, marked dry_run, and the driver only logs
// "would ban"; a dry-run ban is never a real firewall ban, and the
// gateway (stage 5) must show it as simulated.
//
// Stage 8 adds three guards, all automatic-ban only: the circuit
// breaker (too many auto-bans in a window pauses auto-banning),
// the max-active-bans cap, and the audit log. A manual ban by an
// admin bypasses the breaker and the cap — it is an explicit
// decision, not an automatic one — and is handled in commands.go.
type banner struct {
	store  *store.Store
	driver firewall.Driver
	wl     *whitelist.List
	log    *slog.Logger
	dryRun bool
	// breaker is nil only in tests that build a banner by hand;
	// handleBan treats a nil breaker as "never trips".
	breaker *breaker.Breaker
	// maxActiveBans caps active bans; zero disables the cap (only
	// reachable from tests — config validation rejects zero).
	maxActiveBans int

	bans    atomic.Uint64
	skipped atomic.Uint64
	// refused counts auto-bans the breaker or the max-active-bans
	// cap turned down; skipped counts whitelist refusals only.
	refused atomic.Uint64
}

// handleBan bans one detected IP, unless it is whitelisted, the
// circuit breaker is open, or the max-active-bans cap is reached.
func (b *banner) handleBan(ctx context.Context, det detector.Detection, r *rules.Rule) {
	if b.wl.Contains(det.IP) {
		b.skipped.Add(1)
		b.log.Warn("skipping ban for whitelisted IP", "rule", det.RuleName, "ip", det.IP.String(), "offence", det.Offence)
		return
	}
	// The manual whitelist is checked here too, not only for manual
	// bans: an admin who whitelisted an IP expects no ban from any
	// path. A failed check refuses the ban rather than applying it
	// on an unknown whitelist.
	if b.store != nil {
		whitelisted, err := b.store.IsManualWhitelisted(ctx, det.IP)
		if err != nil {
			b.log.Error("manual whitelist check failed, skipping ban", "rule", det.RuleName, "ip", det.IP.String(), "error", err)
			return
		}
		if whitelisted {
			b.skipped.Add(1)
			b.log.Warn("skipping ban for manually whitelisted IP", "rule", det.RuleName, "ip", det.IP.String(), "offence", det.Offence)
			return
		}
	}
	now := time.Now()
	// The breaker only ever refuses automatic bans. A re-arm is
	// reported the same way as a trip: a critical log line, a
	// Redis event, and a persisted events row.
	if b.breaker != nil {
		if allow, rearmed := b.breaker.Allow(now); !allow {
			b.refused.Add(1)
			b.log.Warn("circuit breaker open, refusing auto-ban", "rule", det.RuleName, "ip", det.IP.String(), "offence", det.Offence)
			return
		} else if rearmed {
			b.log.Info("circuit breaker re-armed, automatic bans resumed")
			b.publishBreakerEvent(ctx, store.CircuitBreakerEvent{
				State: "closed", MaxBans: b.breaker.Max(),
				WindowSeconds:   int(b.breaker.Window().Seconds()),
				CooldownSeconds: int(b.breaker.Cooldown().Seconds()),
				RearmedAt:       &now,
			})
		}
	}
	// The cap counts every active ban, dry-run rows included: a
	// dry-run ban still occupies a row the operator must review. A
	// failed count refuses the ban — the row SaveBan would write
	// cannot be trusted without it, and the detection itself is
	// already stored.
	if b.store != nil && b.maxActiveBans > 0 {
		n, err := b.store.CountActiveBans(ctx)
		if err != nil {
			b.log.Error("active ban count failed, refusing auto-ban", "rule", det.RuleName, "ip", det.IP.String(), "error", err)
			return
		}
		if n >= b.maxActiveBans {
			b.refused.Add(1)
			b.log.Error("max active bans reached, refusing auto-ban", "rule", det.RuleName, "ip", det.IP.String(), "active_bans", n, "max_active_bans", b.maxActiveBans)
			b.store.PublishRaw(ctx, map[string]any{
				"type": "ban_refused", "reason": "max_active_bans",
				"rule": det.RuleName, "ip": det.IP.String(),
				"active_bans": n, "max_active_bans": b.maxActiveBans,
			})
			return
		}
	}
	duration := r.BanDuration(det.Offence)
	var expiresAt *time.Time
	if duration != nil {
		t := time.Now().Add(time.Duration(*duration) * time.Second)
		expiresAt = &t
	}
	if b.store == nil && !b.dryRun {
		// A live ban with nowhere to record it would be unenforceable
		// and invisible to the UI, so it is skipped, not applied.
		b.log.Error("cannot ban without a database, skipping", "rule", det.RuleName, "ip", det.IP.String())
		return
	}
	var banID string
	if b.store != nil {
		id, err := b.store.SaveBan(ctx, det.IP, det.Message(), det.RuleID, expiresAt, b.dryRun)
		if err != nil {
			b.log.Error("failed to store ban", "rule", det.RuleName, "ip", det.IP.String(), "error", err)
			return
		}
		banID = id
		// The audit row is the trace for this ban: actor "agent"
		// (actor_id NULL — the agent has no user account), target
		// the ban id. A failed audit write is logged, not fatal:
		// the ban itself already stands.
		if err := b.store.SaveAuditLog(ctx, "ban.create", "ban", banID, map[string]any{
			"ip": det.IP.String(), "rule": det.RuleName, "offence": det.Offence,
			"duration_seconds": duration, "dry_run": b.dryRun, "source": "detection",
		}); err != nil {
			b.log.Error("failed to write ban audit log, ban still stands", "ban_id", banID, "error", err)
		}
	}
	if err := b.driver.Ban(ctx, det.IP, duration); err != nil {
		b.log.Error("failed to apply firewall ban, will retry on restart", "rule", det.RuleName, "ip", det.IP.String(), "error", err)
		return
	}
	// Only a ban that was actually created counts toward the
	// breaker: refusals above never reach this line.
	if b.breaker != nil && b.breaker.Record(now) {
		_, _, inWindow := b.breaker.State(now)
		b.log.Error("circuit breaker tripped, automatic bans paused",
			"bans_in_window", inWindow, "max_bans", b.breaker.Max(),
			"window_seconds", int(b.breaker.Window().Seconds()),
			"cooldown_seconds", int(b.breaker.Cooldown().Seconds()))
		b.publishBreakerEvent(ctx, store.CircuitBreakerEvent{
			State: "open", BansInWindow: inWindow, MaxBans: b.breaker.Max(),
			WindowSeconds:   int(b.breaker.Window().Seconds()),
			CooldownSeconds: int(b.breaker.Cooldown().Seconds()),
			OpenedAt:        &now,
		})
	}
	if b.store != nil {
		b.store.PublishBan(ctx, store.BanEvent{
			IP: det.IP.String(), Rule: det.RuleName, Offence: det.Offence,
			DurationSeconds: duration, ExpiresAt: expiresAt, DryRun: b.dryRun,
			Reason: det.Message(),
		})
	}
	b.bans.Add(1)
}

// publishBreakerEvent sends a breaker transition on the events
// channel and persists it as an events row, so the gateway can
// derive the breaker state from the database and the alert checker
// can mail the admin. Without a store there is nowhere to publish
// or persist to; the log line in handleBan is the only record.
func (b *banner) publishBreakerEvent(ctx context.Context, e store.CircuitBreakerEvent) {
	if b.store == nil {
		return
	}
	payload := map[string]any{
		"type": "circuit_breaker", "state": e.State,
		"bans_in_window": e.BansInWindow, "max_bans": e.MaxBans,
		"window_seconds": e.WindowSeconds, "cooldown_seconds": e.CooldownSeconds,
	}
	if e.OpenedAt != nil {
		payload["opened_at"] = e.OpenedAt
	}
	if e.RearmedAt != nil {
		payload["rearmed_at"] = e.RearmedAt
	}
	b.store.PublishRaw(ctx, payload)
	if err := b.store.SaveCircuitBreakerEvent(ctx, e); err != nil {
		b.log.Error("failed to persist circuit breaker event", "state", e.State, "error", err)
	}
}

// restore runs once at startup. Bans that expired while the agent
// was down are revoked without touching the firewall. Active bans
// are re-applied to the firewall, except dry-run rows, which were
// never in it. In dry-run nothing is re-applied at all.
func (b *banner) restore(ctx context.Context) {
	if b.store == nil {
		return
	}
	expired, err := b.store.ListExpiredBans(ctx)
	if err != nil {
		b.log.Error("failed to list expired bans for restore", "error", err)
		return
	}
	for _, bn := range expired {
		if err := b.store.RevokeBan(ctx, bn.ID); err != nil {
			b.log.Error("failed to revoke expired ban", "ban_id", bn.ID, "ip", bn.IP.String(), "error", err)
			continue
		}
		b.log.Info("revoked ban that expired while agent was down", "ip", bn.IP.String(), "reason", bn.Reason)
		// The revocation is an agent action, so it is audited as
		// one (actor "agent", source "restore"); without this row
		// the ban would show as revoked with no trace of who did it.
		if err := b.store.SaveAuditLog(ctx, "ban.revoke", "ban", bn.ID, map[string]any{
			"ip": bn.IP.String(), "reason": bn.Reason, "source": "restore",
		}); err != nil {
			b.log.Error("failed to write unban audit log", "ban_id", bn.ID, "error", err)
		}
	}
	active, err := b.store.ListActiveBans(ctx)
	if err != nil {
		b.log.Error("failed to list active bans for restore", "error", err)
		return
	}
	if b.dryRun {
		b.log.Info("dry-run: skipping restore of active bans", "bans", len(active))
		return
	}
	restored := 0
	for _, bn := range active {
		if bn.DryRun {
			continue
		}
		var remaining *int
		if bn.ExpiresAt != nil {
			secs := int(time.Until(*bn.ExpiresAt).Seconds())
			if secs <= 0 {
				continue
			}
			remaining = &secs
		}
		if err := b.driver.Ban(ctx, bn.IP, remaining); err != nil {
			b.log.Error("failed to restore ban", "ip", bn.IP.String(), "error", err)
			continue
		}
		restored++
	}
	b.log.Info("firewall bans restored", "restored", restored, "active", len(active))
}

// expireSweep unbans expired bans. A failed unban leaves the row
// unrevoked, so the next sweep retries it. Permanent bans
// (expires_at NULL) never appear in the expired list. Dry-run rows
// are only revoked in the database; they were never in the firewall.
func (b *banner) expireSweep(ctx context.Context) {
	if b.store == nil {
		return
	}
	expired, err := b.store.ListExpiredBans(ctx)
	if err != nil {
		b.log.Error("failed to list expired bans", "error", err)
		return
	}
	for _, bn := range expired {
		if !bn.DryRun && !b.dryRun {
			if err := b.driver.Unban(ctx, bn.IP); err != nil {
				b.log.Error("failed to unban expired IP, will retry", "ip", bn.IP.String(), "error", err)
				continue
			}
		}
		if err := b.store.RevokeBan(ctx, bn.ID); err != nil {
			b.log.Error("failed to revoke expired ban", "ban_id", bn.ID, "ip", bn.IP.String(), "error", err)
			continue
		}
		if err := b.store.SaveAuditLog(ctx, "ban.revoke", "ban", bn.ID, map[string]any{
			"ip": bn.IP.String(), "reason": bn.Reason, "source": "auto-unban",
		}); err != nil {
			b.log.Error("failed to write unban audit log", "ban_id", bn.ID, "error", err)
		}
		if bn.DryRun || b.dryRun {
			b.log.Info("dry-run ban expired, revoked in database only", "ip", bn.IP.String())
		} else {
			b.log.Info("ban expired, unbanned", "ip", bn.IP.String())
		}
	}
}
