const express = require('express');
const net = require('node:net');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { pageSchema } = require('../validate');
const { badRequest } = require('../errors');
const geoip = require('../geoip');
const { isWhitelisted, isWhitelistedAny } = require('../whitelist');

const router = express.Router();

// GET /api/ips/:ip — everything the IP detail page needs in one
// call: geo (via the GeoIP interface, "unknown" when no database
// is configured), first/last seen and total event count, top rules
// for this IP, the paginated event history (newest first), all bans
// for the IP (active and revoked), a few sample requests taken from
// the raw evidence of the latest events, and whether the IP is
// whitelisted (agent-config ranges plus manual_lists entries).
router.get('/:ip', requireAuth, async (req, res, next) => {
  try {
    const ip = req.params.ip;
    if (!net.isIP(ip)) {
      return next(badRequest('ip must be a valid IP address'));
    }
    const query = pageSchema.parse(req.query);
    const offset = (query.page - 1) * query.limit;

    const { rows: summaryRows } = await db.query(
      `SELECT count(*) AS total,
              min(occurred_at) AS first_seen,
              max(occurred_at) AS last_seen
         FROM events WHERE ip = $1::inet`,
      [ip],
    );
    const summary = summaryRows[0];

    const { rows: topRuleRows } = await db.query(
      `SELECT r.name AS rule, count(*) AS count
         FROM events e LEFT JOIN rules r ON r.id = e.rule_id
        WHERE e.ip = $1::inet
        GROUP BY r.name ORDER BY count DESC, r.name ASC NULLS LAST LIMIT 5`,
      [ip],
    );

    const { rows: eventRows } = await db.query(
      `SELECT e.id, e.occurred_at, e.source, host(e.ip) AS ip, e.severity, e.message,
              r.name AS rule_name, e.raw
         FROM events e LEFT JOIN rules r ON r.id = e.rule_id
        WHERE e.ip = $1::inet
        ORDER BY e.occurred_at DESC, e.created_at DESC
        LIMIT $2 OFFSET $3`,
      [ip, query.limit, offset],
    );

    const { rows: banRows } = await db.query(
      `SELECT b.id, host(b.ip) AS ip, b.reason, b.rule_id, r.name AS rule_name,
              b.banned_by, b.dry_run, b.expires_at, b.revoked_at, b.created_at
         FROM bans b LEFT JOIN rules r ON r.id = b.rule_id
        WHERE b.ip = $1::inet
        ORDER BY b.created_at DESC`,
      [ip],
    );

    const geo = await geoip.lookup(ip);
    const whitelisted = await isWhitelistedAny(ip);

    // Sample requests come from the raw evidence of the latest
    // events, not from a separate table: method/path/status are
    // what the parser recorded for the triggering log line.
    const samples = eventRows.slice(0, 3).map((row) => ({
      occurred_at: row.occurred_at,
      rule: row.rule_name,
      method: (row.raw && row.raw.method) || null,
      path: (row.raw && row.raw.path) || null,
      status: (row.raw && row.raw.status) || null,
      user_agent: (row.raw && row.raw.user_agent) || null,
      raw: (row.raw && row.raw.raw) || null,
    }));

    return res.json({
      ip,
      geo: { ip, ...geo },
      whitelisted,
      whitelisted_by_config: isWhitelisted(ip),
      first_seen: summary.first_seen,
      last_seen: summary.last_seen,
      total_events: Number(summary.total),
      top_rules: topRuleRows.map((r) => ({ rule: r.rule, count: Number(r.count) })),
      events: eventRows.map((row) => ({
        id: row.id,
        occurred_at: row.occurred_at,
        source: row.source,
        ip: row.ip,
        severity: row.severity,
        message: row.message,
        rule_name: row.rule_name,
      })),
      page: query.page,
      limit: query.limit,
      total: Number(summary.total),
      bans: banRows.map((row) => ({
        id: row.id,
        ip: row.ip,
        reason: row.reason,
        rule_id: row.rule_id,
        rule_name: row.rule_name,
        banned_by: row.banned_by,
        dry_run: row.dry_run,
        expires_at: row.expires_at,
        revoked_at: row.revoked_at,
        created_at: row.created_at,
      })),
      samples,
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
