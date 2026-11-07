package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"logbanner/internal/breaker"
	"logbanner/internal/detector"
	"logbanner/internal/firewall"
	"logbanner/internal/rules"
	"logbanner/internal/store"
	"logbanner/internal/whitelist"
)

// Stage 6: manual ban/unban commands apply through the firewall
// driver (dry-run here, so only the driver's counters move), and a
// whitelisted IP is refused before the driver is touched.
func TestHandleManualCommand(t *testing.T) {
	ctx := context.Background()
	log := slog.Default()
	wl, err := whitelist.New([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	driver := firewall.NewDryRun(log)
	b := &banner{store: nil, driver: driver, wl: wl, log: log, dryRun: false}

	duration := 3600
	b.handleManualCommand(ctx, manualCommand{
		Type: "ban", IP: "203.0.113.5", DurationSeconds: &duration, Reason: "manual test", DryRun: false,
	})
	if driver.Banned() != 1 {
		t.Errorf("Banned() = %d, want 1 after a live manual ban command", driver.Banned())
	}

	// A whitelisted IP is refused, never reaching the driver.
	b.handleManualCommand(ctx, manualCommand{
		Type: "ban", IP: "10.0.0.9", DurationSeconds: &duration, Reason: "must not ban", DryRun: false,
	})
	if driver.Banned() != 1 {
		t.Errorf("Banned() = %d, want still 1 after a whitelisted ban command", driver.Banned())
	}

	// A dry-run command only logs, it does not apply.
	b.handleManualCommand(ctx, manualCommand{
		Type: "ban", IP: "203.0.113.6", DurationSeconds: &duration, Reason: "dry run", DryRun: true,
	})
	if driver.Banned() != 1 {
		t.Errorf("Banned() = %d, want still 1 after a dry-run ban command", driver.Banned())
	}

	b.handleManualCommand(ctx, manualCommand{Type: "unban", IP: "203.0.113.5", DryRun: false})
	if driver.Unbanned() != 1 {
		t.Errorf("Unbanned() = %d, want 1 after a manual unban command", driver.Unbanned())
	}

	// An invalid IP and an unknown type are ignored, not fatal.
	b.handleManualCommand(ctx, manualCommand{Type: "ban", IP: "not-an-ip"})
	b.handleManualCommand(ctx, manualCommand{Type: "explode", IP: "203.0.113.5"})
	if driver.Banned() != 1 || driver.Unbanned() != 1 {
		t.Errorf("Banned() = %d Unbanned() = %d after invalid commands, want 1 and 1", driver.Banned(), driver.Unbanned())
	}
}

// Stage 8: the circuit breaker trips after more than max auto-bans
// in the window, refuses further auto-bans while open, and does
// not count refusals toward the window.
func TestHandleBanCircuitBreaker(t *testing.T) {
	ctx := context.Background()
	log := slog.Default()
	wl, err := whitelist.New([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	driver := firewall.NewDryRun(log)
	b := &banner{
		store: nil, driver: driver, wl: wl, log: log, dryRun: true,
		breaker: breaker.New(2, 600, 600),
	}
	r := &rules.Rule{
		Name: "ssh-brute-force", BanSeconds: 3600,
		Escalation: []*int{intPtr(3600), intPtr(14400), intPtr(86400), nil},
	}
	ban := func(ip string, offence int) {
		b.handleBan(ctx, detector.Detection{
			RuleName: "ssh-brute-force", IP: net.ParseIP(ip),
			Count: 5, Window: 5 * time.Minute, Offence: offence,
		}, r)
	}
	ban("203.0.113.5", 1)
	ban("203.0.113.6", 1)
	if open, _, _ := b.breaker.State(time.Now()); open {
		t.Error("breaker open after 2 bans with max 2, want closed")
	}
	ban("203.0.113.7", 1) // third ban inside the window trips it
	if open, _, inWindow := b.breaker.State(time.Now()); !open || inWindow != 3 {
		t.Errorf("breaker state after trip = open %v inWindow %d, want true 3", open, inWindow)
	}
	if driver.Banned() != 3 {
		t.Errorf("driver banned = %d, want 3 (the tripping ban is still created)", driver.Banned())
	}
	ban("203.0.113.8", 1) // refused while open
	if driver.Banned() != 3 {
		t.Errorf("driver banned = %d after a refused ban, want still 3", driver.Banned())
	}
	if b.refused.Load() != 1 {
		t.Errorf("refused = %d, want 1", b.refused.Load())
	}
}

// Stage 8: a manual ban command bypasses the breaker — it is an
// admin's explicit decision, not an automatic ban.
func TestManualCommandBypassesBreaker(t *testing.T) {
	ctx := context.Background()
	log := slog.Default()
	wl, err := whitelist.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	driver := firewall.NewDryRun(log)
	b := &banner{
		store: nil, driver: driver, wl: wl, log: log, dryRun: true,
		breaker: breaker.New(1, 600, 600),
	}
	// Trip the breaker with auto-bans first (dry-run: recorded and
	// counted, never applied to a firewall).
	r := &rules.Rule{Name: "ssh-brute-force", BanSeconds: 3600}
	for _, ip := range []string{"203.0.113.5", "203.0.113.6"} {
		b.handleBan(ctx, detector.Detection{RuleName: "ssh-brute-force", IP: net.ParseIP(ip), Count: 5, Offence: 1}, r)
	}
	if open, _, _ := b.breaker.State(time.Now()); !open {
		t.Fatal("breaker should be open after 2 auto-bans with max 1")
	}
	// Flip to live mode for the manual command: with dry-run on,
	// the command would only be logged, not applied.
	b.dryRun = false
	duration := 3600
	b.handleManualCommand(ctx, manualCommand{
		Type: "ban", IP: "203.0.113.9", DurationSeconds: &duration, Reason: "manual while breaker open", DryRun: false,
	})
	if driver.Banned() != 3 {
		t.Errorf("driver banned = %d, want 3 (2 auto + 1 manual that bypassed the open breaker)", driver.Banned())
	}
}

func intPtr(n int) *int { return &n }

// testPool connects to the database from DATABASE_URL, like the
// store tests; tests skip when it is unset or unreachable.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set, skipping Postgres-backed banner test")
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

// Stage 8: the max-active-bans cap refuses auto-bans at the cap
// and lets them through below it, and an auto-ban writes its audit
// row (actor "agent", target the ban id).
func TestHandleBanMaxActiveBansAndAudit(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := store.NewWithDB(tx, nil, nil)

	expires := time.Now().Add(time.Hour)
	before, err := s.CountActiveBans(ctx)
	if err != nil {
		t.Fatalf("CountActiveBans before: %v", err)
	}
	for _, ip := range []string{"203.0.113.11", "203.0.113.12"} {
		if _, err := s.SaveBan(ctx, net.ParseIP(ip), "seeded active ban", "", &expires, false); err != nil {
			t.Fatalf("seed ban %s: %v", ip, err)
		}
	}

	log := slog.Default()
	wl, err := whitelist.New([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	driver := firewall.NewDryRun(log)
	b := &banner{
		store: s, driver: driver, wl: wl, log: log, dryRun: true,
		breaker: breaker.New(100, 600, 600), maxActiveBans: before + 2,
	}
	r := &rules.Rule{
		Name: "ssh-brute-force", BanSeconds: 3600,
		Escalation: []*int{intPtr(3600), intPtr(14400), intPtr(86400), nil},
	}
	b.handleBan(ctx, detector.Detection{
		RuleName: "ssh-brute-force", IP: net.ParseIP("203.0.113.13"),
		Count: 5, Window: 5 * time.Minute, Offence: 1,
	}, r)
	if driver.Banned() != 0 {
		t.Errorf("driver banned = %d at the cap, want 0 (auto-ban refused)", driver.Banned())
	}
	if b.refused.Load() != 1 {
		t.Errorf("refused = %d, want 1", b.refused.Load())
	}
	n, err := s.CountActiveBans(ctx)
	if err != nil {
		t.Fatalf("CountActiveBans: %v", err)
	}
	if n != before+2 {
		t.Errorf("active bans = %d after a refused ban, want %d (seeded 2 on top of %d existing)", n, before+2, before)
	}

	// Below the cap the same ban goes through and is audited.
	b.maxActiveBans = 100
	b.handleBan(ctx, detector.Detection{
		RuleName: "ssh-brute-force", IP: net.ParseIP("203.0.113.13"),
		Count: 5, Window: 5 * time.Minute, Offence: 1,
	}, r)
	if driver.Banned() != 1 {
		t.Errorf("driver banned = %d below the cap, want 1", driver.Banned())
	}
	var (
		actorID *string
		action  string
		details map[string]any
		target  string
	)
	err = tx.QueryRow(ctx, `
		SELECT actor_id, action, target_id, details FROM audit_logs
		WHERE action = 'ban.create' AND details->>'ip' = '203.0.113.13'`,
	).Scan(&actorID, &action, &target, &details)
	if err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if actorID != nil {
		t.Errorf("audit actor_id = %q, want NULL (agent actor)", *actorID)
	}
	if details["actor"] != "agent" || details["source"] != "detection" {
		t.Errorf("audit details = %v, want actor agent source detection", details)
	}
	var banID string
	if err := tx.QueryRow(ctx, `SELECT id FROM bans WHERE ip = '203.0.113.13'::inet`).Scan(&banID); err != nil {
		t.Fatalf("read ban row: %v", err)
	}
	if target != banID {
		t.Errorf("audit target = %q, want the ban id %q", target, banID)
	}
	if details["duration_seconds"] != float64(3600) {
		t.Errorf("audit duration_seconds = %v, want 3600", details["duration_seconds"])
	}
}

// Stage 8: a manual ban command the agent actually applies is
// audited (actor "agent", target the ban id the gateway sent).
// A live firewall is not needed to cover the audit write: the
// dry-run driver counts the apply, and the audit path is the same
// code the nftables driver would reach. A dry-run command writes
// no audit row — nothing was applied, and the gateway already
// wrote the ban.create row for the ban itself.
func TestHandleManualCommandWritesAudit(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	s := store.NewWithDB(tx, nil, nil)

	banID, err := s.SaveBan(ctx, net.ParseIP("203.0.113.21"), "manual test", "", nil, false)
	if err != nil {
		t.Fatalf("SaveBan: %v", err)
	}
	log := slog.Default()
	wl, err := whitelist.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	driver := firewall.NewDryRun(log)
	b := &banner{
		store: s, driver: driver, wl: wl, log: log, dryRun: false,
		breaker: breaker.New(100, 600, 600), maxActiveBans: 100,
	}
	duration := 3600
	b.handleManualCommand(ctx, manualCommand{
		Type: "ban", BanID: banID, IP: "203.0.113.21",
		DurationSeconds: &duration, Reason: "manual test", DryRun: false,
	})
	if driver.Banned() != 1 {
		t.Fatalf("driver banned = %d, want 1", driver.Banned())
	}
	var (
		actorID *string
		details map[string]any
		target  string
	)
	err = tx.QueryRow(ctx, `
		SELECT actor_id, target_id, details FROM audit_logs
		WHERE action = 'ban.create' AND target_id = $1`, banID,
	).Scan(&actorID, &target, &details)
	if err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if actorID != nil {
		t.Errorf("audit actor_id = %q, want NULL (agent actor)", *actorID)
	}
	if target != banID {
		t.Errorf("audit target = %q, want the ban id %q", target, banID)
	}
	if details["actor"] != "agent" || details["source"] != "manual-command" {
		t.Errorf("audit details = %v, want actor agent source manual-command", details)
	}

	// A dry-run command applies nothing and audits nothing: the
	// audit count is unchanged by it.
	var before int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_logs`).Scan(&before); err != nil {
		t.Fatalf("count audit rows before dry-run: %v", err)
	}
	b.handleManualCommand(ctx, manualCommand{
		Type: "ban", BanID: banID, IP: "203.0.113.22",
		DurationSeconds: &duration, Reason: "dry run", DryRun: true,
	})
	var after int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_logs`).Scan(&after); err != nil {
		t.Fatalf("count audit rows after dry-run: %v", err)
	}
	if after != before {
		t.Errorf("audit rows = %d after a dry-run command, want %d (unchanged)", after, before)
	}
}
