// Package store persists detections to Postgres and publishes them
// to Redis for the gateway (stage 5 consumes the channel).
//
// Storage decision: only detections are persisted, not every parsed
// event. Storing every line would flood the events table at the rate
// of the access log (the http-flood rule alone fires at 300 requests
// a minute per IP), and the events table is defined as one row per
// detection (occurred_at, source, ip, rule_id, severity, message,
// raw JSONB). The raw JSONB column keeps the evidence for a
// detection: count, window, first/last seen, offence number and the
// triggering log line.
//
// Redis publishing never blocks detection: a publish failure is
// counted and logged, and the detection is still stored.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"logbanner/internal/detector"
	"logbanner/internal/rules"
)

// Channel is the Redis pub/sub channel detections are published on.
const Channel = "logbanner:events"

// CommandsChannel is the Redis pub/sub channel the agent listens on
// for manual ban/unban commands from the gateway (stage 6). It is
// separate from Channel so commands never appear in the live feed.
const CommandsChannel = "logbanner:commands"

// DB is the subset of pgx used here. *pgxpool.Pool satisfies it, and
// so does pgx.Tx, which is what the tests use so they can roll back.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store writes detections to Postgres and publishes them on Redis.
type Store struct {
	db    DB
	pool  *pgxpool.Pool // non-nil when this Store owns the pool
	redis *redis.Client // nil when Redis is unavailable; publishing is skipped
	log   *slog.Logger

	stored        atomic.Uint64
	publishFailed atomic.Uint64
}

// New connects to Postgres (DatabaseURL, required) and Redis
// (RedisAddr, optional). A Redis failure only disables publishing
// and is logged; a Postgres failure is returned, and the caller
// runs detection-only without storage.
func New(ctx context.Context, databaseURL, redisAddr string, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &Store{db: pool, pool: pool, log: log}
	if redisAddr != "" {
		client := redis.NewClient(&redis.Options{Addr: redisAddr, DialTimeout: 2 * time.Second})
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := client.Ping(pingCtx).Err(); err != nil {
			log.Warn("redis unavailable, detections will not be published", "addr", redisAddr, "error", err)
			_ = client.Close()
		} else {
			s.redis = client
		}
	}
	return s, nil
}

// NewWithDB builds a Store over an existing DB handle (a pool or a
// transaction) and Redis client, for tests. Either may be nil.
func NewWithDB(db DB, redisClient *redis.Client, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{db: db, redis: redisClient, log: log}
}

// Close releases the pool and the Redis client, if owned.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.redis != nil {
		_ = s.redis.Close()
	}
}

// Stored returns how many detections have been written to Postgres.
func (s *Store) Stored() uint64 { return s.stored.Load() }

// PublishFailures returns how many Redis publishes failed.
func (s *Store) PublishFailures() uint64 { return s.publishFailed.Load() }

// SyncRules inserts every loaded rule into the rules table by
// name and returns the row id and enabled flag for each. The
// database is the single source of truth from stage 6: the YAML
// file only seeds rules that do not exist yet, and an existing row
// is never overwritten here — an admin edit made through the
// gateway (threshold, pattern, enabled, ...) survives the next
// agent reload. Rules that are in the database but no longer in
// the file are left alone.
func (s *Store) SyncRules(ctx context.Context, rs []rules.Rule) (map[string]rules.Meta, error) {
	const insertSQL = `
		INSERT INTO rules (name, source, pattern, threshold, window_seconds, ban_seconds, action, escalation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
		ON CONFLICT (name) DO NOTHING`
	meta := make(map[string]rules.Meta, len(rs))
	for _, r := range rs {
		esc, err := json.Marshal(escalationJSON(r.Escalation))
		if err != nil {
			return nil, fmt.Errorf("sync rule %q: marshal escalation: %w", r.Name, err)
		}
		if _, err := s.db.Exec(ctx, insertSQL,
			r.Name, r.Source, r.Pattern, r.Threshold, r.WindowSeconds, r.BanSeconds, r.Action, string(esc),
		); err != nil {
			return nil, fmt.Errorf("sync rule %q: %w", r.Name, err)
		}
		var m rules.Meta
		err = s.db.QueryRow(ctx, `SELECT id, enabled FROM rules WHERE name = $1`, r.Name).Scan(&m.ID, &m.Enabled)
		if err != nil {
			return nil, fmt.Errorf("sync rule %q: %w", r.Name, err)
		}
		meta[r.Name] = m
	}
	return meta, nil
}

// LoadRules reads every rule row from the database, compiled and
// ready to match. This is what the detector runs from stage 6: the
// YAML file seeds, the database decides.
func (s *Store) LoadRules(ctx context.Context) ([]rules.Rule, error) {
	rows, err := s.db.Query(ctx, `
		SELECT name, source, pattern, threshold, window_seconds, ban_seconds,
		       action, escalation, id, enabled
		  FROM rules ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	defer rows.Close()
	var out []rules.Rule
	for rows.Next() {
		var name, source, pattern, action, id string
		var threshold, windowSeconds, banSeconds int
		var escJSON []byte
		var enabled bool
		if err := rows.Scan(&name, &source, &pattern, &threshold, &windowSeconds, &banSeconds,
			&action, &escJSON, &id, &enabled); err != nil {
			return nil, fmt.Errorf("load rules: scan: %w", err)
		}
		var escalation []*int
		if err := json.Unmarshal(escJSON, &escalation); err != nil {
			return nil, fmt.Errorf("load rule %q: bad escalation: %w", name, err)
		}
		r, err := rules.CompileFields(name, source, pattern, threshold, windowSeconds, banSeconds, action, escalation)
		if err != nil {
			return nil, fmt.Errorf("load rule %q: %w", name, err)
		}
		r.ID = id
		r.Enabled = enabled
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	return out, nil
}

// IsManualWhitelisted reports whether ip matches a whitelist entry
// in manual_lists (a single IP or a CIDR range). Values that do not
// parse are skipped with a warning instead of failing the check,
// because a bad stored value must never block banning an attacker
// or crash the agent. An error is returned only when the table
// itself cannot be read; the caller then refuses the ban, because
// a ban decided on an unknown whitelist is not safe to apply.
func (s *Store) IsManualWhitelisted(ctx context.Context, ip net.IP) (bool, error) {
	if ip == nil {
		return false, nil
	}
	rows, err := s.db.Query(ctx, `SELECT value FROM manual_lists WHERE kind = 'whitelist'`)
	if err != nil {
		return false, fmt.Errorf("read manual whitelist: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return false, fmt.Errorf("read manual whitelist: %w", err)
		}
		if parsed := net.ParseIP(value); parsed != nil {
			if parsed.Equal(ip) {
				return true, nil
			}
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			s.log.Warn("ignoring invalid manual whitelist entry", "value", value)
			continue
		}
		if network.Contains(ip) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("read manual whitelist: %w", err)
	}
	return false, nil
}

// escalationJSON converts the escalation steps to a JSON array; a nil
// element encodes as null (permanent from that offence on). A nil
// slice becomes an empty array, not JSON null.
func escalationJSON(steps []*int) []any {
	out := make([]any, 0, len(steps))
	for _, step := range steps {
		if step == nil {
			out = append(out, nil)
		} else {
			out = append(out, *step)
		}
	}
	return out
}

// SaveDetection writes one detection to the events table and
// publishes it on Redis. A Redis failure is logged and counted but
// does not fail the save; a Postgres failure is returned.
func (s *Store) SaveDetection(ctx context.Context, d detector.Detection) error {
	raw, err := json.Marshal(map[string]any{
		"rule":           d.RuleName,
		"count":          d.Count,
		"window_seconds": int(d.Window.Seconds()),
		"first_seen":     d.FirstSeen,
		"last_seen":      d.LastSeen,
		"offence":        d.Offence,
		"method":         d.Sample.Method,
		"path":           d.Sample.Path,
		"status":         d.Sample.Status,
		"user_agent":     d.Sample.UserAgent,
		"raw":            d.Sample.Raw,
	})
	if err != nil {
		return fmt.Errorf("marshal detection raw: %w", err)
	}
	const sql = `
		INSERT INTO events (occurred_at, source, ip, rule_id, severity, message, raw)
		VALUES ($1, $2, $3::inet, $4::uuid, $5, $6, $7::jsonb)`
	var ruleID any
	if d.RuleID != "" {
		ruleID = d.RuleID
	}
	if _, err := s.db.Exec(ctx, sql,
		d.LastSeen, d.Source, d.IP.String(), ruleID, d.Severity, d.Message(), string(raw),
	); err != nil {
		return fmt.Errorf("insert detection event: %w", err)
	}
	s.stored.Add(1)
	s.publish(ctx, d)
	return nil
}

// publish sends the detection JSON to the Redis channel. It is
// best-effort: any failure is counted and logged, never returned.
func (s *Store) publish(ctx context.Context, d detector.Detection) {
	if s.redis == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"type":        "detection",
		"rule":        d.RuleName,
		"ip":          d.IP.String(),
		"source":      d.Source,
		"severity":    d.Severity,
		"count":       d.Count,
		"offence":     d.Offence,
		"message":     d.Message(),
		"occurred_at": d.LastSeen,
	})
	if err != nil {
		s.publishFailed.Add(1)
		s.log.Error("marshal detection for redis publish", "error", err)
		return
	}
	pubCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.redis.Publish(pubCtx, Channel, payload).Err(); err != nil {
		s.publishFailed.Add(1)
		s.log.Warn("redis publish failed, detection still stored", "error", err)
	}
}

// OffenceCount returns how many bans already exist for this IP
// under this rule: the ban history, which is what the offence
// number is derived from. A ban counts whether it is active,
// expired, or revoked, and whether it was a dry-run, because it
// still records a past offence. The match is by rule_id when the
// rule has one; rows written before the rule was synced (rule_id
// NULL) match by the rule name at the start of the reason instead.
// The caller adds one for the ban about to be created.
func (s *Store) OffenceCount(ctx context.Context, ip net.IP, ruleID, ruleName string) (int, error) {
	if ip == nil {
		return 0, nil
	}
	var n int
	err := s.db.QueryRow(ctx, `
		SELECT count(*) FROM bans
		WHERE ip = $1::inet
		  AND (rule_id = $2::uuid OR (rule_id IS NULL AND reason LIKE $3))`,
		ip.String(), nullUUID(ruleID), ruleName+":%",
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count offences for %s rule %q: %w", ip.String(), ruleName, err)
	}
	return n, nil
}

// nullUUID turns an empty id into a nil driver value so the
// $2::uuid cast above never sees an empty string.
func nullUUID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

// CountActiveBans returns how many bans are currently in force
// (not revoked, permanent or not yet expired). The max-active-bans
// cap in the agent is checked against this number.
func (s *Store) CountActiveBans(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `
		SELECT count(*) FROM bans
		WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count active bans: %w", err)
	}
	return n, nil
}

// SaveAuditLog writes one audit_logs row. The agent has no user
// account, so actor_id is NULL and the actor is named in details
// ({"actor": "agent", ...}); that is the documented agent actor
// from stage 8, and it keeps the foreign key to users intact.
// An audit failure is returned — the caller decides whether the
// ban it describes can proceed without its audit row.
func (s *Store) SaveAuditLog(ctx context.Context, action, targetType, targetID string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	details["actor"] = "agent"
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	const sql = `
		INSERT INTO audit_logs (actor_id, action, target_type, target_id, details)
		VALUES (NULL, $1, $2, $3, $4::jsonb)`
	if _, err := s.db.Exec(ctx, sql, action, targetType, targetID, string(raw)); err != nil {
		return fmt.Errorf("insert audit log %s: %w", action, err)
	}
	return nil
}

// CircuitBreakerEvent is one persisted breaker transition, stored
// as an events row so the gateway and the UI can read the breaker
// state from the database instead of trusting a log line. It has
// no IP and no rule, so both are NULL; source is "agent" and the
// raw JSONB carries the state and the counts.
type CircuitBreakerEvent struct {
	State           string // "open" or "closed"
	BansInWindow    int
	MaxBans         int
	WindowSeconds   int
	CooldownSeconds int
	OpenedAt        *time.Time // set when the breaker opened
	RearmedAt       *time.Time // set when it re-armed
}

// SaveCircuitBreakerEvent persists a breaker transition as a
// critical event. The alert checker (stage 8) reads the latest
// such row to decide whether to mail the admin.
func (s *Store) SaveCircuitBreakerEvent(ctx context.Context, e CircuitBreakerEvent) error {
	raw, err := json.Marshal(map[string]any{
		"type":             "circuit_breaker",
		"state":            e.State,
		"bans_in_window":   e.BansInWindow,
		"max_bans":         e.MaxBans,
		"window_seconds":   e.WindowSeconds,
		"cooldown_seconds": e.CooldownSeconds,
		"opened_at":        e.OpenedAt,
		"rearmed_at":       e.RearmedAt,
	})
	if err != nil {
		return fmt.Errorf("marshal circuit breaker event: %w", err)
	}
	message := "circuit breaker " + e.State
	if e.State == "open" {
		message = fmt.Sprintf("circuit breaker open: %d auto-bans in %d seconds (max %d)", e.BansInWindow, e.WindowSeconds, e.MaxBans)
	} else {
		message = "circuit breaker re-armed, automatic bans resumed"
	}
	const sql = `
		INSERT INTO events (occurred_at, source, ip, rule_id, severity, message, raw)
		VALUES (now(), 'agent', NULL, NULL, 'critical', $1, $2::jsonb)`
	if _, err := s.db.Exec(ctx, sql, message, string(raw)); err != nil {
		return fmt.Errorf("insert circuit breaker event: %w", err)
	}
	return nil
}

// PublishRaw publishes an arbitrary JSON payload on the events
// channel. Best-effort like the other publishers: a failure is
// counted and logged, never returned.
func (s *Store) PublishRaw(ctx context.Context, payload map[string]any) {
	if s.redis == nil {
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		s.publishFailed.Add(1)
		s.log.Error("marshal event for redis publish", "error", err)
		return
	}
	pubCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.redis.Publish(pubCtx, Channel, raw).Err(); err != nil {
		s.publishFailed.Add(1)
		s.log.Warn("redis publish failed", "error", err)
	}
}

// Ban is one row of the bans table.
type Ban struct {
	ID        string
	IP        net.IP
	Reason    string
	RuleID    string
	ExpiresAt *time.Time // nil means a permanent ban
	DryRun    bool       // true when the ban was only recorded, never applied to the firewall
	CreatedAt time.Time
}

// SaveBan inserts a ban row and returns its id. expiresAt nil means
// permanent. The row is written before the firewall is touched, so
// if the firewall call fails, the next agent start restores the ban
// from this row instead of losing it.
func (s *Store) SaveBan(ctx context.Context, ip net.IP, reason, ruleID string, expiresAt *time.Time, dryRun bool) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("cannot save ban for nil IP")
	}
	const sql = `
		INSERT INTO bans (ip, reason, rule_id, expires_at, dry_run)
		VALUES ($1::inet, $2, $3::uuid, $4, $5)
		RETURNING id`
	var rule any
	if ruleID != "" {
		rule = ruleID
	}
	var id string
	if err := s.db.QueryRow(ctx, sql, ip.String(), reason, rule, expiresAt, dryRun).Scan(&id); err != nil {
		return "", fmt.Errorf("insert ban for %s: %w", ip.String(), err)
	}
	return id, nil
}

// ListActiveBans returns bans that are still in force: not revoked,
// and either permanent or not yet expired. Dry-run rows are
// included; the caller must skip them when re-applying to the
// firewall, since they were never in it.
func (s *Store) ListActiveBans(ctx context.Context) ([]Ban, error) {
	return s.listBans(ctx, `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`)
}

// ListExpiredBans returns bans whose expiry has passed and which
// have not been revoked yet: these are what the auto-unban loop and
// the startup restore pass revoke.
func (s *Store) ListExpiredBans(ctx context.Context) ([]Ban, error) {
	return s.listBans(ctx, `revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= now()`)
}

func (s *Store) listBans(ctx context.Context, where string) ([]Ban, error) {
	// where is one of the two fixed clauses above, never user input.
	rows, err := s.db.Query(ctx, `
		SELECT id, host(ip), reason, rule_id, expires_at, dry_run, created_at
		FROM bans WHERE `+where+` ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list bans: %w", err)
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var ipText string
		var ruleID *string
		if err := rows.Scan(&b.ID, &ipText, &b.Reason, &ruleID, &b.ExpiresAt, &b.DryRun, &b.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ban row: %w", err)
		}
		b.IP = net.ParseIP(ipText)
		if ruleID != nil {
			b.RuleID = *ruleID
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list bans: %w", err)
	}
	return out, nil
}

// RevokeBan marks a ban revoked. It is a no-op for a ban that is
// already revoked.
func (s *Store) RevokeBan(ctx context.Context, id string) error {
	if _, err := s.db.Exec(ctx, `UPDATE bans SET revoked_at = now() WHERE id = $1::uuid AND revoked_at IS NULL`, id); err != nil {
		return fmt.Errorf("revoke ban %s: %w", id, err)
	}
	return nil
}

// BanEvent is the payload published when a ban is applied (or, in
// dry-run, recorded). DurationSeconds nil means permanent.
type BanEvent struct {
	IP              string
	Rule            string
	Offence         int
	DurationSeconds *int
	ExpiresAt       *time.Time
	DryRun          bool
	Reason          string
}

// PublishBan sends the ban JSON on the same channel as detections,
// with type "ban" so the gateway can tell it apart. Best-effort
// like detections: a failure is counted and logged, never returned.
func (s *Store) PublishBan(ctx context.Context, e BanEvent) {
	if s.redis == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"type":             "ban",
		"ip":               e.IP,
		"rule":             e.Rule,
		"offence":          e.Offence,
		"duration_seconds": e.DurationSeconds,
		"expires_at":       e.ExpiresAt,
		"dry_run":          e.DryRun,
		"reason":           e.Reason,
	})
	if err != nil {
		s.publishFailed.Add(1)
		s.log.Error("marshal ban for redis publish", "error", err)
		return
	}
	pubCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.redis.Publish(pubCtx, Channel, payload).Err(); err != nil {
		s.publishFailed.Add(1)
		s.log.Warn("redis publish failed, ban still stored", "error", err)
	}
}
