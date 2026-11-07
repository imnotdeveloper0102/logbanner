# logbanner

Log analysis and automatic IP blocking. The agent tails real logs
(nginx, Apache, SSH auth.log, application logs), matches detection rules,
and pushes bans to the firewall. Admins watch events, review bans, and
edit rules through the web UI.

Chỉ quét/chặn tài sản của mình hoặc được phép, đừng để lọt secret hay tài khoản thật vào project

## What it is

One agent watches log files and bans attacking IPs; one web UI shows
what happened and lets an admin intervene. There is no cloud
component and no data leaves the host except the alert emails the
admin configures.

- Agent (Go 1.22): tails logs, parses lines, matches rules,
  records detections, bans IPs through nftables or iptables/ipset.
- Gateway (Node.js 20, Express): REST API, JWT auth, WebSocket
  live feed, manual bans, rule edits, GeoIP lookups.
- Admin service (PHP 8.2+, PDO): manual whitelist/blacklist
  management, daily/weekly reports (JSON/CSV/PDF), email alerts.
- Data (Postgres 16, Redis 7): Postgres holds events, bans, rules,
  audit rows and alert state; Redis carries the live event feed and
  the manual-ban commands from gateway to agent.

```
logbanner/
  frontend/        React 18 app (Vite, React Router, plain CSS)
  gateway/         Node: REST, auth, WebSocket
  agent/           Go: tailing, detection, firewall
  admin-service/   PHP: lists, reports, email alerts
  db/migrations/   numbered SQL migrations (001-009)
  deploy/          docker-compose.yml, nginx config, systemd unit
  rules/           default detection rules (YAML)
```

## Quick start

### With Docker Compose

```sh
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD, JWT_ACCESS_SECRET, SERVICE_TOKEN,
# ADMIN_EMAIL and ADMIN_PASSWORD
cd deploy
docker compose --env-file ../.env up --build
```

| Service       | Address              |
| ------------- | -------------------- |
| nginx         | http://localhost:8080 |
| frontend (dev)| http://localhost:5173 |
| gateway       | http://localhost:3001 |
| admin-service | http://localhost:8081 |
| postgres      | localhost:5432        |
| redis         | localhost:6379        |

The gateway seeds the admin account from `ADMIN_EMAIL` /
`ADMIN_PASSWORD` on start. nginx writes access logs to the shared
`nginx-logs` volume, which the agent reads.

### Without Docker

Postgres 16 and Redis 7 must be running locally. Apply the
migrations in order (they are plain SQL; there is no migration
runner):

```sh
for f in db/migrations/*.sql; do psql "$DATABASE_URL" -f "$f"; done
```

Gateway:

```sh
cd gateway
npm install
npm run seed
npm run dev
```

Frontend:

```sh
cd frontend
npm install
npm run dev
```

Admin service:

```sh
cd admin-service
composer install
php -S localhost:8081 -t public
```

Agent:

```sh
cd agent
go test ./...
go run ./cmd/agent -config ../deploy/agent.yaml.example
```

## Environment variables

All of them live in `.env` (copy `.env.example`, never commit
`.env`). The agent also reads its own YAML file; where both exist,
the environment variable wins for the agent's secrets and paths
(see `agent/internal/config/config.go`).

| Variable | Used by | Meaning |
| -------- | ------- | ------- |
| `POSTGRES_USER` | compose | Postgres role created for the stack (default `logbanner`). |
| `POSTGRES_PASSWORD` | compose, agent, gateway, admin service | Postgres password. Test value in `.env`; change it before any real use. |
| `POSTGRES_DB` | compose | Database name (default `logbanner`). |
| `DATABASE_URL` | agent, gateway, admin service | Full Postgres URL, e.g. `postgres://logbanner:<password>@localhost:5432/logbanner`. |
| `REDIS_URL` | gateway | Redis URL for the gateway (default `redis://localhost:6379`). |
| `PORT` | gateway | Gateway listen port (default `3001`). |
| `JWT_ACCESS_SECRET` | gateway | Secret that signs access tokens. Rotate it if it leaks; every issued token stops working. |
| `CORS_ORIGIN` | gateway | Allowed browser origin (default `http://localhost:5173`). |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | gateway | Seed admin created on gateway start when both are set. |
| `SERVICE_TOKEN` | gateway, admin service | Shared secret for gateway-to-admin-service calls. The admin service rejects requests without it. |
| `ADMIN_SERVICE_PORT` | nothing | Defined for local dev; no code reads it. In dev the admin service listens on the port given to `php -S`; in compose it is published as `8081`. |
| `ADMIN_SERVICE_URL` | gateway | Base URL the gateway proxies report and list import/export calls to (default `http://localhost:8081`). |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_SECURE` | admin service | SMTP server for alert mail. `SMTP_SECURE` is empty, `tls`, or `ssl`. With `SMTP_HOST` unset nothing is sent and the checker logs a warning instead. `SMTP_FROM` must be a valid address with a dotted domain — PHPMailer rejects a single-label domain such as `logbanner@localhost` (that was the old default; it is fixed in this repo). |
| `ALERT_TO` | admin service | Admin mailbox that receives alert mail. |
| `ALERT_WAVE_THRESHOLD` | admin service | Attack-wave alert: at least this many detections in the window (default `50`). |
| `ALERT_WAVE_WINDOW_MINUTES` | admin service | Wave window in minutes (default `10`). |
| `ALERT_WAVE_THROTTLE_MINUTES` | admin service | At most one wave mail per this many minutes (default `60`). |
| `AGENT_DRY_RUN` | agent, gateway | `true` (default) records bans without touching the firewall. The gateway uses the same flag for manual bans. |
| `AGENT_CONFIG_PATH` | gateway | Path of the live agent config file; used for the sources page and the gateway's whitelist check. Unset means the gateway reports no sources instead of inventing any. |
| `AGENT_STATE_DIR` | agent, gateway | Directory the agent writes per-source offsets and `sources-status.json` into; the gateway reads the status file for live parse counts. |
| `GEOIP_DB_PATH` | gateway | Path of a MaxMind GeoLite2 `.mmdb` file. Unset means every lookup returns `country: "unknown"` and `topCountries` stays empty. |
| `AGENT_MAX_ACTIVE_BANS` | agent | Max active bans at once (default `1000`). Past the cap, new automatic bans are refused; manual admin bans are not capped. |
| `AGENT_CB_MAX_BANS` | agent | Circuit breaker trips after more than this many auto-bans in the window (default `20`). |
| `AGENT_CB_WINDOW_SECONDS` | agent | Breaker window in seconds (default `600`). |
| `AGENT_CB_COOLDOWN_SECONDS` | agent | Breaker re-arms this many seconds after tripping (default `600`). |

## Agent configuration

`deploy/agent.yaml.example` is the documented example; copy it to
`/etc/logbanner/agent.yaml` on a real host (or mount it into the
agent container). The compose agent runs on defaults plus the
`AGENT_*` environment variables, because no config file is mounted
into that container.

```yaml
dry_run: true
firewall_driver: nftables
whitelist:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
rules_path: /etc/logbanner/rules/defaults.yaml
database_url: "postgres://logbanner:<password>@localhost:5432/logbanner"
redis_addr: "localhost:6379"
state_dir: /var/lib/logbanner
max_active_bans: 1000
circuit_breaker:
  max_bans: 20
  window_seconds: 600
  cooldown_seconds: 600
sources:
  - path: /var/log/nginx/access.log
    format: nginx
  - path: /var/log/auth.log
    format: ssh
```

- `dry_run` (default `true`): the agent still writes bans rows,
  marked `dry_run=true`, and logs `would ban <ip> for <duration>`
  (or `would ban (permanent)`), but never calls the firewall and
  does not even require the `nft` binary. A dry-run ban is never a
  real firewall ban: restore never re-applies it and auto-unban
  never unbans it in the firewall; it is only revoked in the
  database when it expires. The UI labels dry-run bans
  "simulated". Flip it off only after verifying the driver on the
  target host.
- `firewall_driver`: `nftables` (default) or `iptables`.
  `nftables` uses a table `inet logbanner` with an `input` filter
  chain that drops packets from two sets, `logbanner_v4`
  (`ipv4_addr`) and `logbanner_v6` (`ipv6_addr`), both with
  `flags timeout`. A timed ban adds the IP with
  `timeout <seconds>s`; a permanent ban adds it with no timeout.
  `iptables` uses two ipset sets (`hash:ip`, per-element timeout,
  `timeout 0` is permanent) plus `iptables`/`ip6tables` INPUT
  rules. Both drivers shell out with arguments as separate argv
  entries, never through a shell, and only after the IP is
  validated. In live mode a missing binary, or a table/set setup
  that fails, stops the agent at startup instead of running and
  silently banning nothing. The agent runs as an unprivileged user
  with only `CAP_NET_ADMIN` (`deploy/systemd/logbanner-agent.service`);
  the compose agent service gets the same capability via `cap_add`.
- `whitelist`: CIDRs or single IPs checked before every ban, no
  exceptions. Loopback (`127.0.0.0/8` and `::1`) is always
  whitelisted and needs no entry. Defaults to the RFC1918 ranges
  when unset; set `whitelist: []` to whitelist nothing extra. Put
  the admin's own IPs here. A detection for a whitelisted IP is
  still stored and published, but the ban is skipped and a warning
  is logged. Bad CIDRs fail config load. Changing `dry_run`,
  `firewall_driver` or `whitelist` needs an agent restart; SIGHUP
  reloads rules only.
- `state_dir`: per-source read offsets (one `.offset` file per
  source, written atomically) and `sources-status.json`, which the
  gateway reads for the log-sources page. Defaults to `./var`;
  on a real host use `/var/lib/logbanner`.
- `sources`: one entry per tailed file, with `path` and `format`.
  A file that does not exist yet is waited on (a warning is logged
  once, tailing starts when it appears). Log rotation is followed
  by inode change; truncation resets to the start of the file. On
  the first run the agent starts at the end of the file, so old
  history is not replayed; after that a restart resumes from the
  persisted offset. A line without a trailing newline is held
  until it completes.
- `max_active_bans` and `circuit_breaker`: see "How the pieces fit
  together" below. Changing them needs a restart; SIGHUP logs a
  warning that they changed instead of applying them.

Run with `-debug` to see every parsed event and unparsable line in
the JSON logs; without it, only the startup line, a summary every
30 seconds, and the final counts on shutdown are logged.

## Rules

`rules/defaults.yaml` holds the default rules. Each rule has a
name, log source, pattern, threshold, window, first ban length,
action, and escalation steps.

```yaml
rules:
  - name: http-login-brute-force
    source: nginx
    pattern: "POST /login|POST /wp-login.php|POST /xmlrpc.php"
    threshold: 10
    window_seconds: 300
    ban_seconds: 3600
    action: ban
    escalation: [3600, 14400, 86400, null]
```

`escalation` lists the ban length in seconds for offence 2, 3,
...; `null` means a permanent ban from that offence on. `action`
is `ban` or `log` (`log` only records the detection, it never
bans). Rules are validated at load: names must be unique,
`threshold`, `window_seconds` and `ban_seconds` must be above zero,
`action` must be `ban` or `log`, escalation steps must be above
zero, and the pattern must compile. A bad file stops the agent at
startup with an error instead of running with no rules.

### Pattern semantics

A rule's `pattern` is one string, interpreted by prefix. It is a
Go regexp, matched unanchored.

| Pattern | Meaning |
| ------- | ------- |
| `*` | matches every event of the rule's source (used by `http-flood`) |
| `status=404` | matches an event whose HTTP status is exactly 404 |
| `status=4xx` | matches any 4xx status |
| `ua:<regex>` | matches the regex against the event's User-Agent |
| `<regex>` | otherwise matched against `METHOD PATH` for HTTP sources, and against the raw log line for the `ssh` source |

The ssh case needs the raw line because the ssh parser normalises
`Message` to an outcome word (`failed`, `accepted`), so `Failed
password` only still appears in the raw line. A rule applies only
to events whose log format equals its `source`, so an `nginx` rule
never fires on Apache logs; copy the rule with `source: apache` if
both are wanted.

### How to write a new rule

Add an entry to `rules/defaults.yaml` (or a copy of it pointed at
by `rules_path`), then reload the agent with SIGHUP (below) or
restart it. Example: flag any request whose User-Agent mentions a
scanner:

```yaml
  - name: malicious-bot
    source: nginx
    pattern: "ua:(?i)(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|hydra|nuclei|wpscan|acunetix|nessus|burpsuite|zgrab|whatweb)"
    threshold: 1
    window_seconds: 60
    ban_seconds: 3600
    action: ban
    escalation: [3600, 14400, 86400, null]
```

The built-in bot list is that `ua:` alternation in
`rules/defaults.yaml`: sqlmap, nikto, nmap, masscan, gobuster,
dirbuster, hydra, nuclei, wpscan, acunetix, nessus, burpsuite,
zgrab, whatweb. It fires on a single matching request (threshold
1) because a scanner User-Agent is malicious on its own, not
something a normal browser sends.

### The database is the source of truth

The YAML file only seeds rules that do not exist yet: on startup
and on SIGHUP the agent inserts missing rules and then loads its
active rule set from the database, so a gateway edit is never
overwritten by a reload. `PATCH /api/rules/:id` (admin only) edits
`threshold`, `window_seconds`, `ban_seconds`, `action`,
`escalation`, `pattern`, and `enabled`; the pattern is validated
with a real regex compile before save, and every edit is written
to `audit_logs` (`action: "rule.update"`) with the old and new
values. An edit takes effect on the next agent reload or restart —
the API response says so, and the rules page repeats it. `name`
and `source` are not editable: the name is the rule's identity.
A rule row that fails to compile stops the reload with an error
and keeps the previous rule set.

### Reloading rules

Send SIGHUP to the agent process: it re-reads the config file and
the rules file, syncs the rules to the database, and atomically
swaps the detector's active rule set. Events already being
processed finish against the old set; the next event sees the new
one. The sync never overwrites the `enabled` flag in the database,
so a rule an admin disabled stays disabled across reloads.
Changing the `sources` list, the firewall settings, the max-bans
cap, or the breaker settings still needs a restart.

```sh
kill -HUP <agent-pid>
```

## Log formats

Built-in formats: `nginx` and `apache` (combined log format),
`ssh` (sshd lines from `auth.log`: failed/accepted password and
publickey, invalid user, connection closed by an authenticating
user), and `json` (one JSON object per line, fields `ip`,
`method`, `path`, `status`, `user_agent`, `user`, `message`,
`timestamp` as RFC3339 or Unix epoch; missing fields are
tolerated). Lines no parser understands are counted as
unparsable and logged at debug level only, so a flood of bad
lines cannot spam the logs.

### Adding a new log format

Add a `formats` entry with a regex using named groups. Recognised
groups are `ip`, `method`, `path`, `status`, `user_agent`, `user`,
`message`, `time` and `timestamp`; `time_format` is a Go time
layout (default RFC3339). Then point a source at it by name:

```yaml
formats:
  - name: app
    regex: '^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) (?P<ip>\S+) (?P<method>\S+) (?P<path>\S+) (?P<status>\d{3}) (?P<message>.*)$'
    time_format: "2006-01-02T15:04:05Z07:00"
sources:
  - path: /var/log/myapp/app.log
    format: app
```

The config is validated at load: unknown formats, duplicate
custom format names, names colliding with built-ins, invalid
regexes, and unknown named groups are all rejected with an error.
A format that needs more than a regex belongs in
`agent/internal/parser/` as a new built-in parser, with tests in
`parser_test.go` and sample lines in `agent/testdata/` (IPs
anonymised to documentation ranges, see
`agent/testdata/README.md`).

## How the pieces fit together

The request path is: log line → parser → detector → ban decision
→ firewall + database + Redis → UI and alerts. Each step keeps
its own record, so a failure in one does not silently lose the
others.

### Detection

The detector counts rule hits per (rule, IP) in a sliding window,
measured on the event's own log timestamp, so a replayed or
backfilled log behaves like a live one. When the count inside the
window reaches the threshold, one detection is emitted and the
counter resets to zero; a continuing attack fires again only after
another full threshold of hits. Expired hits are dropped by a
cleanup pass every minute. Only detections are stored in `events`,
not every parsed event. Severity is `warning`, except `critical`
for a single-hit rule (threshold 1) or a repeat offence
(offence 2+). Redis publishing is best-effort: if Redis is down,
the failure is logged and counted and the detection is still
stored. If Postgres is unreachable or no `database_url` is
configured, the agent keeps detecting and logging, and stores
nothing.

### Ban escalation

`BanDuration(offence)` picks the ban length: offence 1 uses
`ban_seconds`, offence 2 and up walk the `escalation` list, a
`null` step means a permanent ban (`expires_at` NULL), and an
offence past the end of the list keeps the last step (so a
trailing null stays permanent). For the default ssh rule that is
3600, 3600, 14400, 86400, then permanent.

The offence number is derived from the bans history in the
database (`SELECT count(*) FROM bans WHERE ip = ? AND rule ...`),
not only from the detector's in-memory counter. The in-memory
counter resets on restart and when the cleanup pass drops a quiet
(rule, IP), which used to reset escalation to the first ban after
every restart; the database count survives both. The agent takes
the larger of the in-memory offence and the database count plus
one, and re-derives the severity with it, so a repeat offence is
critical even after a restart. A ban counts whether it is active,
expired, revoked, or a dry-run, because it still records a past
offence. This is verified live (see "Verified").

### Circuit breaker

The breaker counts automatic bans in a sliding window
(`circuit_breaker.max_bans` in `circuit_breaker.window_seconds`,
defaults 20 in 600 seconds). When the count passes the limit, it
opens: further auto-bans are refused (detections are still
recorded, bans are not created), a critical line is logged, a
`circuit_breaker` event is published on Redis `logbanner:events`
and persisted as a critical `events` row (source `agent`, no IP,
no rule), and the admin is mailed by the alert checker (below).
After `circuit_breaker.cooldown_seconds` (default 600) the next
auto-ban attempt re-arms it: the window is cleared, the ban
proceeds, and a `closed` event is published and persisted the same
way. Only bans actually created count toward the window; refusals
do not. Manual bans by an admin bypass the breaker entirely — an
explicit decision, not an automatic one. The breaker holds no
database state of its own; a restart starts it closed with an
empty window, and the persisted events are the record of past
trips. `GET /api/circuit-breaker` derives the current state from
the latest persisted breaker event, and the dashboard shows a
banner while it is open.

### Max active bans

`max_active_bans` (default 1000) caps the number of bans in force
at once. Past the cap, a new auto-ban is refused with an error
log line and a `ban_refused` event on Redis (`reason:
"max_active_bans"`); the detection is still stored. The count
covers every active ban, dry-run rows included. A failed count
refuses the ban rather than applying it on an unknown total.
Manual admin bans are not capped.

### Audit log

Every ban, unban, and rule edit is traceable to an actor in
`audit_logs`:

| Action | Actor | Written by |
| ------ | ----- | ---------- |
| `ban.create` (detection) | agent (`actor_id` NULL, `details.actor: "agent"`) | agent, after writing the bans row; target is the ban id, details carry IP, rule, offence, duration, dry-run flag, source `detection` |
| `ban.create` (manual) | the logged-in admin | gateway, when the manual ban is created; the agent writes a second `ban.create` row (actor agent, same ban id, source `manual-command`) when it actually applies the command to the firewall |
| `ban.revoke` (manual unban) | the logged-in admin | gateway; the agent writes a second `ban.revoke` row (actor agent, source `manual-command`) when it applies the unban |
| `ban.revoke` (auto-unban / restore) | agent | agent, when the 60-second sweep unbans an expired ban, or when startup revokes a ban that expired while the agent was down |
| `rule.update` | the logged-in admin | gateway, with old and new values of each changed field |
| `list.create`, `list.delete`, `list.import` | the logged-in admin | gateway (create) or admin service (delete/import, via the gateway proxy, with the user id/role forwarded alongside the service token) |

The agent has no user account, so its rows use `actor_id` NULL
and name the actor in `details` — that is the documented agent
actor, and it keeps the foreign key to `users` intact. A dry-run
manual command writes no agent audit row: nothing was applied,
and the gateway already wrote the `ban.create` row for the ban
itself. Restoring active bans on startup writes no audit row
either: no ban state changed, the firewall was only re-applied.

### Auto-unban and restore

A background sweep every 60 seconds finds bans whose `expires_at`
has passed and `revoked_at` is NULL, calls `Unban` on the driver,
and sets `revoked_at`. A failed unban leaves the row unrevoked,
so the next sweep retries it. Permanent bans are never
auto-unbanned. On startup the agent revokes bans that expired
while it was down (without touching the firewall) and re-applies
the still-active real bans to the firewall, using the remaining
time until `expires_at`. In dry-run the restore is skipped and
logged.

### Manual bans

`POST /api/bans` (admin only) takes `ip` (a single IP, not a
CIDR), `reason`, `duration_seconds` (`null` = permanent), and an
optional `rule_id`. The hard whitelist is checked before the ban:
loopback and the RFC1918 ranges are refused with a 400, and so is
any manual whitelist entry — the gateway reads the whitelist from
the live agent config file at `AGENT_CONFIG_PATH` when it is
readable, and otherwise uses the same default ranges as the agent.
The ban is inserted with `banned_by` set to the admin, published
on Redis `logbanner:events` as a `ban` event, and sent as a
command on `logbanner:commands` for the agent to apply to the
firewall. The agent never writes a bans row for a command — the
gateway's row is the record — so a manual ban cannot be recorded
twice. In dry-run (either the command's `dry_run` flag or the
agent's mode) the agent only logs `manual ban (dry-run): would
ban` and touches nothing. A command for a whitelisted IP is
refused by the agent and logged. `DELETE /api/bans/:id` unbans:
it sets `revoked_at`, publishes an `unban` event and command, and
audit-logs it. Revoking an already-revoked ban is a 409; an
unknown id is a 404.

The manual whitelist (`manual_lists`) is enforced on every ban
path: the gateway refuses a manual ban for it, the agent checks
the table before applying a detection ban, and the agent checks it
again before applying a manual-ban command. A failed whitelist
read refuses the ban rather than applying it on an unknown list.
The agent-config whitelist in `agent.yaml` is separate: it is the
hard list the agent loads at startup, and a change to it needs an
agent restart.

## Gateway API

All endpoints require a logged-in JWT unless noted. Reads are
open to viewer and admin; writes are admin only.

- `GET /health` — gateway health, checks the database.
- `POST /api/auth/register` — create a viewer account.
- `POST /api/auth/login` — returns an access token (15 min), sets
  a refresh cookie (30 days, rotated on use).
- `POST /api/auth/refresh` — rotate the refresh token.
- `POST /api/auth/logout` — revoke the refresh token.
- `GET /api/auth/me` — current user.
- `GET /api/users`, `PATCH /api/users/:id/role` — admin only.
- `GET /api/stats` — events in the last 24h, active bans, enabled
  rules, users, plus `eventsByHour` (24 hourly buckets),
  `topIps` and `topRules` (top 5 in the last 24h), and
  `topCountries` (empty array without a GeoLite2 database; IPs
  that resolve to "unknown" are left out when one is present).
- `GET /api/events?page=1&limit=25&rule=&ip=&severity=&since=` —
  paginated detections, newest first, with the rule name joined
  in. `limit` caps at 100. An invalid IP, severity, or timestamp
  is a 400.
- `GET /api/bans?include_revoked=false` — active bans by default,
  newest first, with rule name, reason, created/expires, and
  `dry_run`. `include_revoked=true` also returns revoked and
  expired rows.
- `POST /api/bans`, `DELETE /api/bans/:id` — manual ban and unban
  (see above).
- `GET /api/rules`, `PATCH /api/rules/:id` — rule list and edit.
- `GET /api/ips/:ip` — geo, first/last seen, total event count,
  top 5 rules for the IP, paginated event history, all bans for
  the IP, three sample requests from the latest events' raw
  evidence, and the whitelisted flag. A 400 for an invalid IP.
- `GET /api/geo/:ip` — `{ip, country, city, subdivision,
  latitude, longitude, database_available}` (see GeoIP below).
- `GET /api/sources` — log sources the agent is tailing, from the
  agent config file at `AGENT_CONFIG_PATH`, merged with live
  metrics from `<state_dir>/sources-status.json` when
  `AGENT_STATE_DIR` is set. Each source reports `status`:
  `reporting` (a status file newer than 120s), `stale` (older),
  or `unavailable` (no report yet), with null counts when there
  is no report — counts are never invented.
- `GET /api/lists`, `POST /api/lists` — manual whitelist/blacklist
  entries (gateway's own endpoints). Delete, import, and export
  are proxied to the admin service (see below).
- `GET /api/reports/daily|weekly` — report proxy (see below).
- `GET /api/circuit-breaker` — breaker state derived from the
  latest persisted breaker event: `open`, `state`
  (`open`/`closed`), `bans_in_window`, `max_bans`,
  `window_seconds`, `opened_at`, `last_event_at`, `message`. With
  no breaker event recorded yet, `open` is false and
  `last_event_at` is null.

Auth details: access tokens are short-lived JWTs kept in memory in
the browser. Refresh tokens are random values stored only as
SHA-256 hashes in `refresh_tokens`, revoked on logout and rotated
on every refresh. Passwords are hashed with bcrypt (cost 12).

### WebSocket live feed

`GET /ws` on the same server as the REST API, implemented with the
`ws` package. Authentication is the JWT access token in the
`token` query parameter of the handshake URL (a WebSocket
handshake cannot carry an `Authorization` header); a missing or
invalid token closes the connection with code 4401. On connect the
server sends a hello (`{"type": "hello", "user": {...}, "counts":
{...}}`) with the current counts, then pushes every message it
receives on Redis channel `logbanner:events` (`detection`, `ban`,
`unban`, `circuit_breaker`, `ban_refused`) to all connected
clients in real time. A malformed Redis message is logged and
skipped; it never closes a client connection. The gateway
subscribes to Redis with the `redis` package; if Redis is down at
startup the gateway still starts and retries the subscription in
the background. The access token lives 15 minutes, so the frontend
refreshes it once on a 4401 close and reconnects; other drops
reconnect with backoff (1s, doubling to a 30s cap).

### Frontend pages

- Overview (`/`): the four stat cards, an hourly events chart for
  the last 24h (plain SVG, no chart library), top IPs and top
  rules tables, and top countries (honest "not configured" while
  the array is empty). A banner appears at the top while the
  circuit breaker is open. Each section has its own loading/empty
  state.
- Live feed (`/live`): events and bans as rows, with pause/resume,
  filters by rule / IP substring / severity, an auto-scroll
  toggle, and a connection status indicator with a manual
  Reconnect button. Shortcuts, active while the feed list has
  focus: `p` pause/resume, `/` focus the rule filter.
- Bans (`/bans`): active bans table, search by IP substring,
  pagination, revoked/expired toggle, unban button, and a manual
  ban form. Admin-only buttons are hidden for viewers.
- IP detail (`/ips/:ip`): geo, totals, event history, ban
  history, sample requests, "Add to whitelist" (admin).
- Rules (`/rules`): list with enabled toggle and edit form, with
  the server syntax-check error shown verbatim and a note on every
  save that the change takes effect on the next agent reload or
  restart.
- Sources (`/sources`): tailed files with format, status, and the
  real parse counts, or honest "unavailable".
- Reports (`/reports`): daily/weekly reports with CSV/PDF
  download.

All server-provided strings render through React, which escapes
them; there is no `dangerouslySetInnerHTML` anywhere in the
frontend.

### GeoIP

`GET /api/geo/:ip` is backed by a MaxMind GeoLite2 `.mmdb` file
when one is configured; the gateway reads it with the `maxmind`
package. No database file ships with the project, and none is
downloaded by the code: GeoLite2 is free but needs a MaxMind
account and a licence key.

1. Create a free account at maxmind.com and generate a licence key
   (Account → Manage License Keys).
2. Download the GeoLite2-City database, for example with the
   permalink form
   `https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=<KEY>&suffix=tar.gz`
   (or GeoLite2-Country for country only), unpack the `.mmdb` from
   the archive, and put it on the gateway host, e.g.
   `/etc/logbanner/GeoLite2-City.mmdb`.
3. Set `GEOIP_DB_PATH=/etc/logbanner/GeoLite2-City.mmdb` in `.env`
   and restart the gateway.

Without a configured file every lookup honestly returns
`country: "unknown"` with the rest null. Locations are never
invented.

## Admin service

All routes require `X-Service-Token`. When the gateway calls on
behalf of a logged-in user it also forwards `X-User-Id` /
`X-User-Role`, which the admin service records in `audit_logs` —
those headers are only trusted alongside a valid service token, so
an unauthenticated caller cannot invent an actor.

### Lists

- `GET /api/lists?kind=whitelist|blacklist` — list entries.
- `POST /api/lists` — add one IP or CIDR (`kind`, `value`,
  `reason`); a duplicate is a 409.
- `DELETE /api/lists/:id` — remove; unknown id is a 404.
- `POST /api/lists/import?kind=whitelist|blacklist` — plain-text
  or CSV body, one entry per line: `value` or `value,reason` (CSV
  quoting applies). Each line is validated on its own; a bad line
  is reported with its line number and skipped, a duplicate is
  counted and skipped, and the import never fails as a whole
  because of one bad line.
- `GET /api/lists/export?kind=whitelist|blacklist` — CSV download.

The gateway keeps its own `GET`/`POST /api/lists` and proxies
delete/import/export to the admin service (`ADMIN_SERVICE_URL`),
so the frontend keeps one base URL and one login.

### Reports

`GET /api/reports/daily?date=YYYY-MM-DD` and
`GET /api/reports/weekly?start=YYYY-MM-DD` (a 7-day window from
that date; default is the Monday of the current week). Dates are
UTC days; a bad date is a 400. Each report has total events,
events by hour (daily) or by day (weekly), top 10 banned IPs, top
10 most-triggered rules, and bans created vs revoked in the
period. `?format=csv` downloads the same data as CSV;
`?format=pdf` downloads a PDF with the same data as plain tables
(Dompdf). Without `format` the response is JSON. Top countries are
reported as unavailable, honestly: events carry no country — the
gateway does GeoIP lookups live but never stores the result, and
`events.raw` carries none. No country is invented.

### Email alerts

`Mailer` (PHPMailer over SMTP) sends three alerts, all driven by
real rows, with state in the `alert_state` table (migration `009`)
so a repeated check never re-sends:

- Critical ban: a ban created in the last hour for which a
  critical-severity event exists for the same IP (and the same
  rule, when the ban names one) in the hour before the ban. Sent
  once per ban id.
- Attack wave: at least `ALERT_WAVE_THRESHOLD` detections
  (default 50) in the last `ALERT_WAVE_WINDOW_MINUTES` minutes
  (default 10), throttled to at most one mail per
  `ALERT_WAVE_THROTTLE_MINUTES` minutes (default 60). A suppressed
  wave is reported as throttled, not sent.
- Circuit breaker: the agent's latest breaker event is still open.
  Sent once per trip, keyed on the trip's `opened_at`; a re-arm
  followed by a new trip is a new `opened_at` and mails again. The
  breaker re-arms itself after its cooldown, so this mail is a
  "look now" notice, not a request to intervene. The mail arrives
  on the next checker run (see the cron line below), so up to 5
  minutes after the trip.

The trigger is the check itself, run two ways (same code):
`POST /api/alerts/check` on the admin service (service token), or
the CLI `bin/check-alerts.php`, which is the cron entry point:

```cron
*/5 * * * * cd /path/to/logbanner/admin-service && /usr/bin/php bin/check-alerts.php >> /var/log/logbanner/alerts.log 2>&1
```

With no SMTP configured the checker logs a clear warning and
sends nothing; a failed send is logged and reported in the check
summary, never claimed as sent. No credentials are hard-coded.

## Generating test traffic

Only ever generate attack traffic against your own machine or lab
— your own SSH/HTTP service, your own nginx, or the test rig
below. Never point these commands at a host you do not own or
have explicit permission to test.

The agent starts tailing at the end of each file on first run, so
append lines after it starts. With Postgres and Redis running and
`.env` filled in:

```sh
cd agent
go build -o /tmp/logbanner-agent ./cmd/agent
mkdir -p /tmp/lb/var && cp ../rules/defaults.yaml /tmp/lb/rules.yaml
touch /tmp/lb/access.log /tmp/lb/auth.log
# config: point rules_path, state_dir and the two sources at /tmp/lb
setsid /tmp/logbanner-agent -config /tmp/lb/agent.yaml > /tmp/lb/agent.log 2>&1 &
redis-cli subscribe logbanner:events > /tmp/lb/redis.log 2>&1 &
# 5 SSH failures -> ssh-brute-force (offence 1, 3600s)
for i in 1 2 3 4 5; do
  echo "$(date '+%b %e %H:%M:%S') host sshd[1234]: Failed password for root from 203.0.113.5 port 5234$i ssh2" >> /tmp/lb/auth.log
done
# 10 failed logins -> http-login-brute-force
D=$(date '+%d/%b/%Y:%H:%M:%S %z')
for i in $(seq 1 10); do
  echo "203.0.113.7 - - [$D] \"POST /login HTTP/1.1\" 401 0 \"-\" \"Mozilla/5.0\"" >> /tmp/lb/access.log
done
# one scanner User-Agent -> malicious-bot (critical)
echo "203.0.113.9 - - [$D] \"GET / HTTP/1.1\" 200 1234 \"-\" \"sqlmap/1.7\"" >> /tmp/lb/access.log
sleep 3
grep '"msg":"detection"' /tmp/lb/agent.log
grep -o '"rule":"[a-z-]*"' /tmp/lb/redis.log | sort | uniq -c
psql "$DATABASE_URL" -c "SELECT r.name, e.ip, e.severity FROM events e LEFT JOIN rules r ON r.id = e.rule_id;"
psql "$DATABASE_URL" -c "SELECT ip, reason, expires_at, dry_run FROM bans;"
```

Repeat the 5 SSH failures to walk the escalation: offence 2 is
3600s again, offence 3 is 14400s, offence 4 is 86400s, offence 5
is permanent (`expires_at` NULL). Restarting the agent between
offences does not reset the count — the offence comes from the
bans history. To trip the breaker on purpose, set
`circuit_breaker.max_bans` low (e.g. 3) in the test config and
keep offending: after the limit the log shows `circuit breaker
tripped` and further auto-bans are refused until the cooldown
passes.

To replay the testdata files instead, copy their lines into the
tailed files after the agent starts (they use documentation IPs
from `agent/testdata/README.md`):

```sh
cat agent/testdata/nginx-access.log >> /tmp/lb/access.log
cat agent/testdata/auth.log >> /tmp/lb/auth.log
```

Note the testdata SSH lines are dated 07/Nov/2026, so replaying
them later counts them against windows around that date, not now.
To test a reload, edit `/tmp/lb/rules.yaml` (for example raise a
threshold), then `kill -HUP <agent-pid>` and watch for the
`config and rules reloaded` line. To test the disabled-rule path,
run `UPDATE rules SET enabled=false WHERE name='http-404-scan';`
in psql, send SIGHUP, and confirm fresh 404s no longer produce a
`http-404-scan` detection. To test auto-unban, insert an expired
dry-run ban and wait for the next 60-second sweep:

```sh
psql "$DATABASE_URL" -c "INSERT INTO bans (ip, reason, expires_at, dry_run) VALUES ('198.51.100.99'::inet, 'test', now() - interval '10 minutes', true);"
# within 60s the agent revokes it and audit-logs ban.revoke with source "auto-unban"
psql "$DATABASE_URL" -c "SELECT ip, revoked_at FROM bans WHERE ip = '198.51.100.99';"
```

Clean up afterwards with `DELETE FROM events; DELETE FROM bans;
DELETE FROM audit_logs; DELETE FROM rules;` (and the test users if
any were created). Real traffic against a live service works the
same way: repeated failed logins to your own lab SSH/HTTP service,
or curl loops against the local nginx — the agent only sees log
lines, so any tool that writes to a tailed log file exercises the
same path.

## Production notes

- `AGENT_DRY_RUN` defaults to `true`. Keep it on until the
  firewall driver is verified on the target host: flip it off,
  ban a test IP, and confirm `nft list set inet logbanner
  logbanner_v4` (or `ipset list logbanner_v4`) shows it, then
  check the IP is actually unreachable.
- The agent runs as an unprivileged user with only
  `CAP_NET_ADMIN` (see `deploy/systemd/logbanner-agent.service`).
  It never runs as root and never gets full `CAP_SYS_ADMIN`.
- Never commit `.env`. Rotate `JWT_ACCESS_SECRET` and
  `SERVICE_TOKEN` if they leak. The `.env` used during
  development holds test passwords — change them before any real
  use.
- The `nginx-logs` volume is the only log path the agent reads in
  dev. On a real host, point `sources` in `agent.yaml` at the real
  log files.
- GeoLite2: obtain a `.mmdb` as described above and set
  `GEOIP_DB_PATH`. Without it, GeoIP returns "unknown" and no
  country data is stored anywhere.
- SMTP: set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`,
  `SMTP_FROM`, `SMTP_SECURE`, and `ALERT_TO`. `SMTP_FROM` must be
  a valid address with a dotted domain (PHPMailer rejects
  `logbanner@localhost`). Add the cron line from the alerts
  section for the checker; without it, no alert mail is ever sent.
- Back up Postgres (`pg_dump`) on the same schedule as anything
  else on the host; the bans history is what escalation is derived
  from, so losing the database resets every IP's offence count to
  the in-memory counter.
- No new migration was needed for stage 8: the breaker state
  lives in the existing `events` table, audit rows in the existing
  `audit_logs` table, and the max-bans cap is a config value.

## Verified vs not verified

Verified on this machine (2026-11-07, after a VM replacement that
reinstalled Go 1.22.12, Postgres 16, Redis 7, PHP 8.3.6, nginx,
composer, and the Docker Compose plugin, and recreated the dev
database from migrations 001-009):

- `go vet ./...` clean; `gofmt` clean; `go test -race ./...`
  passes in `agent/` (breaker, config, detector, firewall, parser,
  rules, store, tailer, whitelist).
- Gateway `npm run lint` and Prettier pass; frontend `npm run
  lint`, Prettier, and `npm run build` pass.
- `php -l` clean on every admin-service file;
  `composer validate` passes.
- `docker compose config` exits 0 in `deploy/` (validate only).
  `nginx -t` passes for `deploy/nginx/nginx.conf`.
- Migrations 001-009 apply cleanly in order on a fresh throwaway
  database (8 tables); no migration 010 was needed.
- Live agent run in dry-run against real appended log lines:
  25 SSH failures from one IP produced 5 bans with durations
  3600, 3600, 14400, 86400, then permanent — including offence 3
  at 14400s after an agent restart in the middle, which proves
  the offence number comes from the bans history, not the
  in-memory counter. Each ban wrote a `ban.create` audit row
  (actor agent, offence and duration in details).
- Live circuit breaker (test config: max 3 in 600s, cooldown 60s):
  the 4th auto-ban tripped it, the 5th was refused with a warning
  log, the trip was published on `logbanner:events` and persisted
  as a critical `events` row, and 65 seconds later the next
  offence re-armed it, created the ban, and published/persisted
  the re-arm. `GET /api/circuit-breaker` returned `open: true`
  while the open event was latest, and `open: false` with the
  re-arm event after.
- Live max-active-bans cap (test config: max 2, 10 active bans):
  an auto-ban was refused with an error log and a `ban_refused`
  event on Redis, and no bans row was written.
- Live auto-unban: a seeded expired dry-run ban was revoked by
  the 60-second sweep with a `ban.revoke` audit row (source
  `auto-unban`); bans that expired while the agent was down were
  revoked at startup with `ban.revoke` rows (source `restore`).
- Live gateway smoke (16 checks, all passing): admin login,
  stats, events, bans, rules, circuit-breaker endpoint (closed
  state and 401 without a token), manual ban created, whitelisted
  manual ban refused (400), unban, double unban (409), rule edit,
  list create, list delete through the admin-service proxy,
  WebSocket hello with a token, WebSocket without a token closed
  with 4401. Audit rows verified in the database for `ban.create`,
  `ban.revoke`, `rule.update`, `list.create`, `list.delete`, and
  `list.import` (via the gateway proxy). The manual ban and unban
  commands reached the agent and were logged as dry-run.
- Live alert check with a dummy local SMTP listener: the breaker
  mail was sent (`[logbanner] Circuit breaker open: 4 auto-bans
  in 600 seconds`, body verified), 9 critical-ban mails were sent
  for the live-test bans, the breaker trip was recorded in
  `alert_state`, and a repeat run sent nothing (already alerted).
  Found and fixed during this check: the default `SMTP_FROM`
  (`logbanner@localhost`) is rejected by PHPMailer's address
  validator, so no mail could ever be sent with it; the default is
  now `logbanner@example.local` in `Mailer.php` and
  `.env.example`, and SMTP_FROM must be a valid dotted address.
- Live reports proxy: daily JSON through `GET /api/reports/daily`
  matched the seeded event counts.
- SIGHUP reload of the agent with the new config fields logs
  `config and rules reloaded` and the agent keeps running.

Not verified:

- The live nftables/iptables drivers against a real firewall.
  This VM has no working `nft` netlink path (`nft list ruleset`
  fails with "Operation not permitted"), and `ipset` is not even
  installed here. The driver code paths that run those commands
  are covered only by argv-construction tests. Verify them on a
  host with `CAP_NET_ADMIN` by flipping `dry_run` off and
  confirming `nft list set inet logbanner logbanner_v4` (or
  `ipset list logbanner_v4`) shows the banned IP, then checking
  the IP is actually unreachable.
- `docker compose up` on a real Docker host. There is no Docker
  daemon in this VM (no socket), so the stack was never started
  with compose here; only `docker compose config` was validated.
  The Dockerfiles were not built here either.
- The frontend pages in a real browser. The API calls they use
  were verified live (see above), and the production build
  passes, but no page was rendered in a browser.
- Mail delivery through a real SMTP server. Only a local dummy
  listener captured the mail; SMTP auth/TLS against a real
  provider was not exercised.
- GeoIP with a real GeoLite2 file. None is available on this
  machine, and downloading one needs a MaxMind licence key.
- The agent's audit row for a manual command applied to a live
  firewall. It is covered by a unit test (store-backed, dry-run
  driver) and the dry-run command path was verified live, but the
  live-firewall apply was not, for the same reason as the drivers
  above.
- Behaviour when the database comes back after being down at
  startup (the agent keeps running log-only until restart), and
  detection under real production log volume. Offset persistence
  is throttled to once per second per file and has not been
  load-tested.

## API (quick reference)

See "Gateway API" above for the full list. The short version:
`GET /health`, `POST /api/auth/login`, `GET /api/stats`,
`GET /api/events`, `GET /api/bans`, `POST /api/bans`,
`DELETE /api/bans/:id`, `GET /api/rules`, `PATCH /api/rules/:id`,
`GET /api/ips/:ip`, `GET /api/geo/:ip`, `GET /api/sources`,
`GET /api/lists`, `GET /api/reports/daily|weekly`,
`GET /api/circuit-breaker`, `GET /ws`.
