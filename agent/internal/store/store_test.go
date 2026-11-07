package store

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"logbanner/internal/detector"
	"logbanner/internal/parser"
	"logbanner/internal/rules"
)

// testPool connects to the database from DATABASE_URL. Tests that need
// Postgres skip with a clear message when it is unset or unreachable;
// they never fake the database.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set, skipping Postgres-backed store test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("cannot connect to Postgres at DATABASE_URL: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("cannot ping Postgres at DATABASE_URL: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func intPtr(n int) *int { return &n }

func TestSyncRulesAndSaveDetection(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	// Everything runs inside a transaction that rolls back, so the
	// test leaves no rows behind in the real database.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, nil, nil)

	// Pre-seed a rule row that an admin disabled, to prove a sync
	// does not clobber the enabled flag.
	_, err = tx.Exec(ctx, `
		INSERT INTO rules (name, source, pattern, threshold, window_seconds, ban_seconds, action, enabled, escalation)
		VALUES ('ssh-brute-force', 'ssh', 'Failed password', 5, 300, 3600, 'ban', false, '[3600, 14400, 86400, null]'::jsonb)`)
	if err != nil {
		t.Fatalf("seed disabled rule: %v", err)
	}

	meta, err := s.SyncRules(ctx, []rules.Rule{
		{Name: "ssh-brute-force", Source: "ssh", Pattern: "Failed password", Threshold: 5, WindowSeconds: 300, BanSeconds: 3600, Action: "ban", Escalation: []*int{intPtr(3600), intPtr(14400), intPtr(86400), nil}},
		{Name: "http-flood", Source: "nginx", Pattern: "*", Threshold: 300, WindowSeconds: 60, BanSeconds: 600, Action: "ban", Escalation: []*int{intPtr(600)}},
	})
	if err != nil {
		t.Fatalf("SyncRules: %v", err)
	}
	if meta["ssh-brute-force"].Enabled {
		t.Error("SyncRules re-enabled a rule the admin had disabled")
	}
	if meta["ssh-brute-force"].ID == "" || meta["http-flood"].ID == "" {
		t.Errorf("SyncRules returned empty ids: %+v", meta)
	}
	if !meta["http-flood"].Enabled {
		t.Error("new rule should be enabled")
	}
	// A second sync keeps the same row (upsert by name, no duplicate).
	meta2, err := s.SyncRules(ctx, []rules.Rule{
		{Name: "http-flood", Source: "nginx", Pattern: "*", Threshold: 300, WindowSeconds: 60, BanSeconds: 600, Action: "ban"},
	})
	if err != nil {
		t.Fatalf("second SyncRules: %v", err)
	}
	if meta2["http-flood"].ID != meta["http-flood"].ID {
		t.Errorf("second sync changed the rule id: %q -> %q", meta["http-flood"].ID, meta2["http-flood"].ID)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	det := detector.Detection{
		RuleName: "http-flood", RuleID: meta["http-flood"].ID, Source: "nginx",
		IP: net.ParseIP("203.0.113.7"), Count: 300, Window: time.Minute,
		FirstSeen: now.Add(-time.Minute), LastSeen: now, Offence: 1, Severity: "warning",
	}
	if err := s.SaveDetection(ctx, det); err != nil {
		t.Fatalf("SaveDetection: %v", err)
	}
	if s.Stored() != 1 {
		t.Errorf("Stored() = %d, want 1", s.Stored())
	}
	var (
		source, severity, message string
		ruleID                    *string
		occurredAt                time.Time
		raw                       map[string]any
	)
	err = tx.QueryRow(ctx, `
		SELECT source, severity, message, rule_id, occurred_at, raw
		FROM events WHERE ip = '203.0.113.7'::inet
	`).Scan(&source, &severity, &message, &ruleID, &occurredAt, &raw)
	if err != nil {
		t.Fatalf("read back event: %v", err)
	}
	if source != "nginx" || severity != "warning" {
		t.Errorf("event row: source %q severity %q, want nginx warning", source, severity)
	}
	if ruleID == nil || *ruleID != meta["http-flood"].ID {
		t.Errorf("event rule_id = %v, want %q", ruleID, meta["http-flood"].ID)
	}
	if message == "" {
		t.Error("event message is empty")
	}
	if raw["count"] != float64(300) || raw["offence"] != float64(1) {
		t.Errorf("event raw = %v, want count 300 offence 1", raw)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 1 {
		t.Errorf("events in tx = %d, want 1", count)
	}
}

func TestSaveBanListAndRevoke(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, nil, nil)

	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	timedID, err := s.SaveBan(ctx, net.ParseIP("203.0.113.5"), "ssh-brute-force: 5 events", "", &expires, false)
	if err != nil {
		t.Fatalf("SaveBan timed: %v", err)
	}
	if timedID == "" {
		t.Error("SaveBan returned an empty id")
	}
	permID, err := s.SaveBan(ctx, net.ParseIP("2001:db8::1"), "malicious-bot", "", nil, false)
	if err != nil {
		t.Fatalf("SaveBan permanent: %v", err)
	}
	if permID == timedID {
		t.Error("two bans got the same id")
	}
	if _, err := s.SaveBan(ctx, net.ParseIP("203.0.113.7"), "http-login-brute-force", "", &expires, true); err != nil {
		t.Fatalf("SaveBan dry-run: %v", err)
	}
	// An already-expired ban, inserted directly so its expiry is in the past.
	if _, err := tx.Exec(ctx, `INSERT INTO bans (ip, reason, expires_at, dry_run) VALUES ('198.51.100.99'::inet, 'old ban', $1, false)`, now.Add(-time.Hour)); err != nil {
		t.Fatalf("seed expired ban: %v", err)
	}

	active, err := s.ListActiveBans(ctx)
	if err != nil {
		t.Fatalf("ListActiveBans: %v", err)
	}
	if len(active) != 3 {
		t.Fatalf("active bans = %d, want 3", len(active))
	}
	byIP := map[string]Ban{}
	for _, b := range active {
		byIP[b.IP.String()] = b
	}
	if byIP["203.0.113.5"].ExpiresAt == nil {
		t.Error("timed ban should have an expiry")
	}
	if byIP["2001:db8::1"].ExpiresAt != nil {
		t.Error("permanent ban should have no expiry")
	}
	if !byIP["203.0.113.7"].DryRun {
		t.Error("dry-run ban should be marked dry_run")
	}
	if byIP["203.0.113.5"].DryRun {
		t.Error("real ban should not be marked dry_run")
	}

	expired, err := s.ListExpiredBans(ctx)
	if err != nil {
		t.Fatalf("ListExpiredBans: %v", err)
	}
	if len(expired) != 1 || expired[0].IP.String() != "198.51.100.99" {
		t.Fatalf("expired bans = %v, want only 198.51.100.99", expired)
	}
	if err := s.RevokeBan(ctx, expired[0].ID); err != nil {
		t.Fatalf("RevokeBan: %v", err)
	}
	expired, err = s.ListExpiredBans(ctx)
	if err != nil {
		t.Fatalf("ListExpiredBans after revoke: %v", err)
	}
	if len(expired) != 0 {
		t.Errorf("expired bans after revoke = %d, want 0", len(expired))
	}
	// Revoking twice is a no-op, not an error.
	if err := s.RevokeBan(ctx, byIP["203.0.113.5"].ID); err != nil {
		t.Fatalf("first RevokeBan: %v", err)
	}
	if err := s.RevokeBan(ctx, byIP["203.0.113.5"].ID); err != nil {
		t.Errorf("second RevokeBan should be a no-op: %v", err)
	}

	if _, err := s.SaveBan(ctx, nil, "nil ip", "", nil, false); err == nil {
		t.Error("SaveBan accepted a nil IP")
	}
}

func TestPublishBan(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	sub := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 2 * time.Second})
	defer sub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sub.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis at %s is not reachable, skipping publish test: %v", addr, err)
	}
	pubsub := sub.Subscribe(ctx, Channel)
	defer pubsub.Close()
	if _, err := pubsub.Receive(ctx); err != nil {
		t.Fatalf("subscribe %s: %v", Channel, err)
	}
	ch := pubsub.Channel()

	pool := testPool(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, sub, nil)

	expires := time.Now().UTC().Add(time.Hour)
	s.PublishBan(ctx, BanEvent{
		IP: "203.0.113.5", Rule: "ssh-brute-force", Offence: 1,
		DurationSeconds: intPtr(3600), ExpiresAt: &expires, DryRun: true,
		Reason: "ssh-brute-force: 5 events",
	})
	select {
	case msg := <-ch:
		var payload map[string]any
		if err := json.Unmarshal([]byte(msg.Payload), &payload); err != nil {
			t.Fatalf("published payload is not JSON: %v", err)
		}
		if payload["type"] != "ban" || payload["ip"] != "203.0.113.5" || payload["rule"] != "ssh-brute-force" {
			t.Errorf("published ban payload = %v", payload)
		}
		if payload["dry_run"] != true || payload["duration_seconds"] != float64(3600) {
			t.Errorf("published ban payload = %v, want dry_run true and duration 3600", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ban message arrived on logbanner:events within 5s")
	}
	if s.PublishFailures() != 0 {
		t.Errorf("PublishFailures() = %d, want 0", s.PublishFailures())
	}
}

func TestPublishDetection(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	sub := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 2 * time.Second})
	defer sub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sub.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis at %s is not reachable, skipping publish test: %v", addr, err)
	}
	pubsub := sub.Subscribe(ctx, Channel)
	defer pubsub.Close()
	// Wait for the subscription to be confirmed before publishing.
	if _, err := pubsub.Receive(ctx); err != nil {
		t.Fatalf("subscribe %s: %v", Channel, err)
	}
	ch := pubsub.Channel()

	pool := testPool(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, sub, nil)
	now := time.Now().UTC()
	det := detector.Detection{
		RuleName: "malicious-bot", Source: "nginx",
		IP: net.ParseIP("203.0.113.9"), Count: 1, Window: time.Minute,
		FirstSeen: now, LastSeen: now, Offence: 1, Severity: "critical",
	}
	if err := s.SaveDetection(ctx, det); err != nil {
		t.Fatalf("SaveDetection: %v", err)
	}
	select {
	case msg := <-ch:
		var payload map[string]any
		if err := json.Unmarshal([]byte(msg.Payload), &payload); err != nil {
			t.Fatalf("published payload is not JSON: %v", err)
		}
		if payload["type"] != "detection" || payload["rule"] != "malicious-bot" || payload["ip"] != "203.0.113.9" {
			t.Errorf("published payload = %v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no message arrived on logbanner:events within 5s")
	}
	if s.PublishFailures() != 0 {
		t.Errorf("PublishFailures() = %d, want 0", s.PublishFailures())
	}
}

func TestPublishFailureDoesNotFailSave(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	// Point Redis at a closed port: publishes must fail, the save
	// must still succeed.
	badRedis := redis.NewClient(&redis.Options{Addr: "localhost:1", DialTimeout: time.Second})
	defer badRedis.Close()
	s := NewWithDB(tx, badRedis, nil)
	now := time.Now().UTC()
	det := detector.Detection{
		RuleName: "http-flood", Source: "nginx",
		IP: net.ParseIP("203.0.113.7"), Count: 300, Window: time.Minute,
		FirstSeen: now, LastSeen: now, Offence: 1, Severity: "warning",
	}
	if err := s.SaveDetection(ctx, det); err != nil {
		t.Fatalf("SaveDetection with dead Redis should still succeed: %v", err)
	}
	if s.PublishFailures() != 1 {
		t.Errorf("PublishFailures() = %d, want 1", s.PublishFailures())
	}
	if s.Stored() != 1 {
		t.Errorf("Stored() = %d, want 1", s.Stored())
	}
}

// Stage 6: the database is the source of truth for rules. A sync
// must not overwrite a threshold an admin edited in the database,
// and LoadRules must return the edited values, compiled.
func TestSyncRulesDoesNotOverwriteDatabaseEdits(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, nil, nil)

	if _, err := s.SyncRules(ctx, []rules.Rule{
		{Name: "http-flood", Source: "nginx", Pattern: "*", Threshold: 300, WindowSeconds: 60, BanSeconds: 600, Action: "ban"},
	}); err != nil {
		t.Fatalf("first SyncRules: %v", err)
	}
	// An admin edit through the gateway: threshold 300 -> 50.
	if _, err := tx.Exec(ctx, `UPDATE rules SET threshold = 50 WHERE name = 'http-flood'`); err != nil {
		t.Fatalf("admin edit: %v", err)
	}
	if _, err := s.SyncRules(ctx, []rules.Rule{
		{Name: "http-flood", Source: "nginx", Pattern: "*", Threshold: 300, WindowSeconds: 60, BanSeconds: 600, Action: "ban"},
	}); err != nil {
		t.Fatalf("second SyncRules: %v", err)
	}
	loaded, err := s.LoadRules(ctx)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("LoadRules returned %d rules, want 1", len(loaded))
	}
	if loaded[0].Threshold != 50 {
		t.Errorf("loaded threshold = %d, want 50 (the database edit, not the YAML value)", loaded[0].Threshold)
	}
	if loaded[0].ID == "" || !loaded[0].Enabled {
		t.Errorf("loaded rule = id %q enabled %v, want an id and enabled", loaded[0].ID, loaded[0].Enabled)
	}
	if !loaded[0].Matches(parser.Event{Source: "nginx", IP: net.ParseIP("203.0.113.7"), Method: "GET", Path: "/"}) {
		t.Error("loaded http-flood rule should match any event of its source")
	}
}

func TestIsManualWhitelisted(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, nil, nil)

	if _, err := tx.Exec(ctx, `INSERT INTO manual_lists (kind, value, reason) VALUES
		('whitelist', '203.0.113.0/24', 'office range'),
		('whitelist', '2001:db8::5', 'single host'),
		('blacklist', '198.51.100.0/24', 'not a whitelist entry'),
		('whitelist', 'not-an-ip', 'bad value must not break the check')`); err != nil {
		t.Fatalf("seed manual_lists: %v", err)
	}
	for ip, want := range map[string]bool{
		"203.0.113.42": true,
		"203.0.114.1":  false,
		"2001:db8::5":  true,
		"2001:db8::6":  false,
		"198.51.100.9": false,
	} {
		got, err := s.IsManualWhitelisted(ctx, net.ParseIP(ip))
		if err != nil {
			t.Fatalf("IsManualWhitelisted(%s): %v", ip, err)
		}
		if got != want {
			t.Errorf("IsManualWhitelisted(%s) = %v, want %v", ip, got, want)
		}
	}
}

// Stage 8: the offence number is derived from the bans history,
// so a restart cannot reset escalation. OffenceCount counts every
// ban row for the IP+rule — active, expired, revoked, dry-run —
// matched by rule_id, or by the rule name at the start of the
// reason when the row predates the rule sync (rule_id NULL).
func TestOffenceCount(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, nil, nil)

	// Real rule rows: bans.rule_id has a foreign key to rules(id).
	var sshRuleID, floodRuleID string
	if err := tx.QueryRow(ctx, `INSERT INTO rules (name, source, pattern, threshold, window_seconds, ban_seconds, action, escalation)
		VALUES ('ssh-brute-force', 'ssh', 'Failed password', 5, 300, 3600, 'ban', '[3600, 14400, 86400, null]'::jsonb) RETURNING id`).Scan(&sshRuleID); err != nil {
		t.Fatalf("seed ssh rule: %v", err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO rules (name, source, pattern, threshold, window_seconds, ban_seconds, action, escalation)
		VALUES ('http-flood', 'nginx', '*', 300, 60, 600, 'ban', '[600]'::jsonb) RETURNING id`).Scan(&floodRuleID); err != nil {
		t.Fatalf("seed flood rule: %v", err)
	}
	ruleID := sshRuleID
	expires := time.Now().Add(time.Hour)
	ip := net.ParseIP("203.0.113.5")
	if _, err := s.SaveBan(ctx, ip, "ssh-brute-force: 5 events", ruleID, &expires, false); err != nil {
		t.Fatalf("SaveBan 1: %v", err)
	}
	if _, err := s.SaveBan(ctx, ip, "ssh-brute-force: 5 events", ruleID, &expires, true); err != nil {
		t.Fatalf("SaveBan 2 (dry-run): %v", err)
	}
	// A row with no rule_id still counts when the reason names the rule.
	if _, err := tx.Exec(ctx, `INSERT INTO bans (ip, reason, rule_id, expires_at, dry_run)
		VALUES ('203.0.113.5'::inet, 'ssh-brute-force: 5 events', NULL, $1, false)`, expires); err != nil {
		t.Fatalf("seed NULL rule_id ban: %v", err)
	}
	// A revoked ban is still history, and a ban for another rule or
	// another IP must not count.
	if _, err := s.SaveBan(ctx, ip, "ssh-brute-force: 5 events", ruleID, &expires, false); err != nil {
		t.Fatalf("SaveBan 4: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE bans SET revoked_at = now() WHERE reason = 'ssh-brute-force: 5 events' AND rule_id IS NULL`); err != nil {
		t.Fatalf("revoke seed ban: %v", err)
	}
	if _, err := s.SaveBan(ctx, ip, "http-flood: 300 events", floodRuleID, &expires, false); err != nil {
		t.Fatalf("SaveBan other rule: %v", err)
	}
	if _, err := s.SaveBan(ctx, net.ParseIP("203.0.113.6"), "ssh-brute-force: 5 events", ruleID, &expires, false); err != nil {
		t.Fatalf("SaveBan other IP: %v", err)
	}

	n, err := s.OffenceCount(ctx, ip, ruleID, "ssh-brute-force")
	if err != nil {
		t.Fatalf("OffenceCount: %v", err)
	}
	if n != 4 {
		t.Errorf("OffenceCount = %d, want 4 (3 with rule_id + 1 revoked NULL-rule row)", n)
	}
	// No rule_id at all: only the reason-prefixed rows count.
	n, err = s.OffenceCount(ctx, ip, "", "ssh-brute-force")
	if err != nil {
		t.Fatalf("OffenceCount without rule id: %v", err)
	}
	if n != 1 {
		t.Errorf("OffenceCount without rule id = %d, want 1 (only the NULL rule_id row)", n)
	}
	// The other rule's ban does not leak into this rule's count.
	n, err = s.OffenceCount(ctx, ip, floodRuleID, "http-flood")
	if err != nil {
		t.Fatalf("OffenceCount other rule: %v", err)
	}
	if n != 1 {
		t.Errorf("OffenceCount for http-flood = %d, want 1", n)
	}
	n, err = s.OffenceCount(ctx, nil, ruleID, "ssh-brute-force")
	if err != nil || n != 0 {
		t.Errorf("OffenceCount(nil IP) = (%d, %v), want (0, nil)", n, err)
	}
}

// Stage 8: the max-active-bans cap is checked against this count:
// not revoked, permanent or not yet expired. Revoked and expired
// rows do not count.
func TestCountActiveBans(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, nil, nil)

	expires := time.Now().Add(time.Hour)
	if _, err := s.SaveBan(ctx, net.ParseIP("203.0.113.5"), "active timed", "", &expires, false); err != nil {
		t.Fatalf("SaveBan active: %v", err)
	}
	if _, err := s.SaveBan(ctx, net.ParseIP("203.0.113.6"), "active permanent", "", nil, false); err != nil {
		t.Fatalf("SaveBan permanent: %v", err)
	}
	if _, err := s.SaveBan(ctx, net.ParseIP("203.0.113.7"), "active dry-run", "", &expires, true); err != nil {
		t.Fatalf("SaveBan dry-run: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bans (ip, reason, expires_at, revoked_at) VALUES ('203.0.113.8'::inet, 'revoked', $1, now())`, expires); err != nil {
		t.Fatalf("seed revoked ban: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bans (ip, reason, expires_at) VALUES ('203.0.113.9'::inet, 'expired', now() - interval '1 hour')`); err != nil {
		t.Fatalf("seed expired ban: %v", err)
	}

	n, err := s.CountActiveBans(ctx)
	if err != nil {
		t.Fatalf("CountActiveBans: %v", err)
	}
	if n != 3 {
		t.Errorf("CountActiveBans = %d, want 3 (timed + permanent + dry-run; revoked and expired excluded)", n)
	}
}

// Stage 8: agent audit rows. actor_id is NULL (the agent has no
// user account) and details name the actor as "agent".
func TestSaveAuditLog(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, nil, nil)

	banID, err := s.SaveBan(ctx, net.ParseIP("203.0.113.5"), "ssh-brute-force: 5 events", "", nil, false)
	if err != nil {
		t.Fatalf("SaveBan: %v", err)
	}
	duration := 3600
	if err := s.SaveAuditLog(ctx, "ban.create", "ban", banID, map[string]any{
		"ip": "203.0.113.5", "rule": "ssh-brute-force", "offence": 2,
		"duration_seconds": duration, "dry_run": false, "source": "detection",
	}); err != nil {
		t.Fatalf("SaveAuditLog ban.create: %v", err)
	}
	if err := s.SaveAuditLog(ctx, "ban.revoke", "ban", banID, map[string]any{
		"ip": "203.0.113.5", "source": "auto-unban",
	}); err != nil {
		t.Fatalf("SaveAuditLog ban.revoke: %v", err)
	}

	var (
		actorID *string
		action  string
		details map[string]any
	)
	rows, err := tx.Query(ctx, `SELECT actor_id, action, details FROM audit_logs ORDER BY created_at`)
	if err != nil {
		t.Fatalf("read audit rows: %v", err)
	}
	defer rows.Close()
	got := 0
	for rows.Next() {
		if err := rows.Scan(&actorID, &action, &details); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		if actorID != nil {
			t.Errorf("agent audit row has actor_id %q, want NULL", *actorID)
		}
		if details["actor"] != "agent" {
			t.Errorf("audit %s details actor = %v, want \"agent\"", action, details["actor"])
		}
		got++
	}
	if got != 2 {
		t.Errorf("audit rows = %d, want 2", got)
	}
}

// Stage 8: a breaker transition persists as a critical events row
// with source "agent" and the state in raw, so the gateway can
// derive the breaker state from the database.
func TestSaveCircuitBreakerEvent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := NewWithDB(tx, nil, nil)

	now := time.Now().UTC()
	if err := s.SaveCircuitBreakerEvent(ctx, CircuitBreakerEvent{
		State: "open", BansInWindow: 21, MaxBans: 20, WindowSeconds: 600, OpenedAt: &now,
	}); err != nil {
		t.Fatalf("SaveCircuitBreakerEvent open: %v", err)
	}
	if err := s.SaveCircuitBreakerEvent(ctx, CircuitBreakerEvent{
		State: "closed", MaxBans: 20, WindowSeconds: 600, RearmedAt: &now,
	}); err != nil {
		t.Fatalf("SaveCircuitBreakerEvent closed: %v", err)
	}

	var (
		source, severity, message string
		raw                       map[string]any
		ip                        *string
	)
	err = tx.QueryRow(ctx, `
		SELECT source, severity, message, raw, host(ip) FROM events
		WHERE source = 'agent' ORDER BY occurred_at ASC LIMIT 1`,
	).Scan(&source, &severity, &message, &raw, &ip)
	if err != nil {
		t.Fatalf("read breaker event: %v", err)
	}
	if source != "agent" || severity != "critical" {
		t.Errorf("breaker event: source %q severity %q, want agent critical", source, severity)
	}
	if ip != nil {
		t.Errorf("breaker event has ip %q, want NULL", *ip)
	}
	if raw["type"] != "circuit_breaker" || raw["state"] != "open" {
		t.Errorf("breaker event raw = %v, want type circuit_breaker state open", raw)
	}
	if raw["bans_in_window"] != float64(21) || raw["max_bans"] != float64(20) {
		t.Errorf("breaker event counts = %v, want bans_in_window 21 max_bans 20", raw)
	}
}
