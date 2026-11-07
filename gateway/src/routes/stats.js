const express = require('express');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const geoip = require('../geoip');

const router = express.Router();

// Counts read straight from the database. Zero means no data yet:
// the agent starts writing events from stage 3. The four original
// fields are unchanged; the breakdowns below are additive.
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT
         (SELECT count(*) FROM events WHERE occurred_at >= now() - interval '24 hours') AS events_24h,
         (SELECT count(*) FROM bans WHERE revoked_at IS NULL
            AND (expires_at IS NULL OR expires_at > now())) AS active_bans,
         (SELECT count(*) FROM rules WHERE enabled) AS rules_enabled,
         (SELECT count(*) FROM users) AS total_users`,
    );
    const row = rows[0];
    const { rows: hourlyRows } = await db.query(
      `SELECT date_trunc('hour', occurred_at) AS hour, count(*) AS count
         FROM events
        WHERE occurred_at >= date_trunc('hour', now()) - interval '23 hours'
        GROUP BY 1 ORDER BY 1`,
    );
    // Fill the hours with no events so the chart always has 24 bars.
    const hourly = [];
    const counts = new Map(
      hourlyRows.map((r) => [new Date(r.hour).toISOString(), Number(r.count)]),
    );
    const start = new Date();
    start.setMinutes(0, 0, 0);
    start.setHours(start.getHours() - 23);
    for (let i = 0; i < 24; i++) {
      const hour = new Date(start.getTime() + i * 60 * 60 * 1000).toISOString();
      hourly.push({ hour, count: counts.get(hour) || 0 });
    }
    const { rows: topIpRows } = await db.query(
      `SELECT host(ip) AS ip, count(*) AS count
         FROM events
        WHERE occurred_at >= now() - interval '24 hours' AND ip IS NOT NULL
        GROUP BY ip ORDER BY count DESC, ip ASC LIMIT 5`,
    );
    const { rows: topRuleRows } = await db.query(
      `SELECT r.name AS rule, count(*) AS count
         FROM events e LEFT JOIN rules r ON r.id = e.rule_id
        WHERE e.occurred_at >= now() - interval '24 hours'
        GROUP BY r.name ORDER BY count DESC, r.name ASC NULLS LAST LIMIT 5`,
    );
    // Top countries come from real GeoIP lookups of the distinct
    // IPs seen in the last 24h. Without a GeoLite2 database there
    // is no country data, so the array stays empty rather than
    // inventing locations; IPs that resolve to "unknown" are left
    // out of the ranking for the same reason.
    let topCountries = [];
    if (geoip.hasDatabase()) {
      const { rows: countryIpRows } = await db.query(
        `SELECT host(ip) AS ip, count(*) AS count
           FROM events
          WHERE occurred_at >= now() - interval '24 hours' AND ip IS NOT NULL
          GROUP BY ip`,
      );
      const byCountry = new Map();
      for (const row of countryIpRows) {
        const result = await geoip.lookup(row.ip);
        if (!result || result.country === 'unknown') {
          continue;
        }
        byCountry.set(result.country, (byCountry.get(result.country) || 0) + Number(row.count));
      }
      topCountries = [...byCountry.entries()]
        .map(([country, count]) => ({ country, count }))
        .sort((a, b) => b.count - a.count || (a.country < b.country ? -1 : 1))
        .slice(0, 5);
    }
    return res.json({
      events24h: Number(row.events_24h),
      activeBans: Number(row.active_bans),
      rulesEnabled: Number(row.rules_enabled),
      totalUsers: Number(row.total_users),
      eventsByHour: hourly,
      topIps: topIpRows.map((r) => ({ ip: r.ip, count: Number(r.count) })),
      topRules: topRuleRows.map((r) => ({ rule: r.rule, count: Number(r.count) })),
      topCountries,
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
