const express = require('express');
const net = require('node:net');
const db = require('../db');
const config = require('../config');
const { requireAuth, requireRole } = require('../middleware/auth');
const { bansQuerySchema, manualBanSchema } = require('../validate');
const { badRequest, notFound, conflict } = require('../errors');
const { isWhitelistedAny } = require('../whitelist');
const redis = require('../redis');

const router = express.Router();

function publicBan(row) {
  return {
    id: row.id,
    ip: row.ip,
    reason: row.reason,
    rule_id: row.rule_id,
    rule_name: row.rule_name,
    banned_by: row.banned_by,
    // dry_run: true means the ban was only recorded, never applied
    // to the firewall; the UI labels it simulated.
    dry_run: row.dry_run,
    expires_at: row.expires_at,
    revoked_at: row.revoked_at,
    created_at: row.created_at,
  };
}

async function writeAudit(actorId, action, targetId, details) {
  await db.query(
    'INSERT INTO audit_logs (actor_id, action, target_type, target_id, details) VALUES ($1, $2, $3, $4, $5::jsonb)',
    [actorId, action, 'ban', targetId, JSON.stringify(details)],
  );
}

// Active bans by default; include_revoked=true also returns revoked
// and expired rows, newest first.
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const query = bansQuerySchema.parse(req.query);
    const where =
      query.include_revoked === 'true'
        ? ''
        : 'WHERE b.revoked_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > now())';
    const { rows: countRows } = await db.query(`SELECT count(*) AS total FROM bans b ${where}`);
    const offset = (query.page - 1) * query.limit;
    const { rows } = await db.query(
      `SELECT b.id, host(b.ip) AS ip, b.reason, b.rule_id, r.name AS rule_name,
              b.banned_by, b.dry_run, b.expires_at, b.revoked_at, b.created_at
         FROM bans b LEFT JOIN rules r ON r.id = b.rule_id
        ${where}
        ORDER BY b.created_at DESC
        LIMIT $1 OFFSET $2`,
      [query.limit, offset],
    );
    return res.json({
      bans: rows.map(publicBan),
      page: query.page,
      limit: query.limit,
      total: Number(countRows[0].total),
    });
  } catch (err) {
    return next(err);
  }
});

// Manual ban. The row is written, published on Redis as an event
// for the live feed, and sent as a command on logbanner:commands
// for the agent to apply to the firewall (stage 6). The agent
// applies it through its firewall driver unless it is in dry-run
// mode, in which case it only logs "would ban (manual)". The agent
// re-checks the whitelist before applying; the gateway refuses
// whitelisted IPs up front so the row is never written for them.
router.post('/', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const body = manualBanSchema.parse(req.body);
    if (!net.isIP(body.ip)) {
      return next(badRequest('ip must be a valid IP address, not a CIDR range'));
    }
    if (await isWhitelistedAny(body.ip)) {
      return next(
        badRequest(
          'Refusing to ban a whitelisted address (loopback, a private/internal range, or a manual whitelist entry)',
        ),
      );
    }
    if (body.rule_id) {
      const { rows } = await db.query('SELECT id FROM rules WHERE id = $1', [body.rule_id]);
      if (rows.length === 0) {
        return next(badRequest('rule_id does not match any rule'));
      }
    }
    const expiresAt =
      body.duration_seconds === null
        ? null
        : new Date(Date.now() + body.duration_seconds * 1000).toISOString();
    const { rows } = await db.query(
      `INSERT INTO bans (ip, reason, rule_id, banned_by, expires_at, dry_run)
       VALUES ($1::inet, $2, $3::uuid, $4::uuid, $5, $6)
       RETURNING id, host(ip) AS ip, reason, rule_id, banned_by, dry_run, expires_at, revoked_at, created_at`,
      [body.ip, body.reason, body.rule_id || null, req.user.sub, expiresAt, config.dryRun],
    );
    const ban = rows[0];
    const { rows: ruleRows } = body.rule_id
      ? await db.query('SELECT name FROM rules WHERE id = $1', [body.rule_id])
      : { rows: [] };
    ban.rule_name = ruleRows[0] ? ruleRows[0].name : null;
    await writeAudit(req.user.sub, 'ban.create', ban.id, {
      ip: body.ip,
      reason: body.reason,
      duration_seconds: body.duration_seconds,
      dry_run: config.dryRun,
      source: 'manual',
    });
    const published = await redis.publish({
      type: 'ban',
      ip: body.ip,
      rule: ban.rule_name,
      offence: null,
      duration_seconds: body.duration_seconds,
      expires_at: expiresAt,
      dry_run: config.dryRun,
      reason: body.reason,
      source: 'manual',
      banned_by: req.user.sub,
    });
    if (!published) {
      console.error('Manual ban recorded but not published to Redis', { ban_id: ban.id });
    }
    // Command for the agent on its own channel. The agent does not
    // write a bans row for this — the row above is the record — it
    // only applies the firewall ban (or logs it in dry-run).
    const commanded = await redis.publishCommand({
      type: 'ban',
      ban_id: ban.id,
      ip: body.ip,
      duration_seconds: body.duration_seconds,
      reason: body.reason,
      dry_run: config.dryRun,
      source: 'manual',
    });
    if (!commanded) {
      console.error('Manual ban recorded but the agent command was not published', {
        ban_id: ban.id,
      });
    }
    return res.status(201).json({ ban: publicBan(ban) });
  } catch (err) {
    return next(err);
  }
});

// Unban: marks the row revoked. Revoking an already-revoked ban is
// a conflict, not a silent success, so a double-click cannot hide
// that the ban was already gone.
router.delete('/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `UPDATE bans SET revoked_at = now()
        WHERE id = $1::uuid AND revoked_at IS NULL
        RETURNING id, host(ip) AS ip, reason, rule_id, banned_by, dry_run, expires_at, revoked_at, created_at`,
      [req.params.id],
    );
    if (rows.length === 0) {
      const { rows: existing } = await db.query('SELECT id FROM bans WHERE id = $1::uuid', [
        req.params.id,
      ]);
      if (existing.length === 0) {
        return next(notFound('Ban not found'));
      }
      return next(conflict('Ban is already revoked'));
    }
    const ban = rows[0];
    const { rows: ruleRows } = ban.rule_id
      ? await db.query('SELECT name FROM rules WHERE id = $1', [ban.rule_id])
      : { rows: [] };
    ban.rule_name = ruleRows[0] ? ruleRows[0].name : null;
    await writeAudit(req.user.sub, 'ban.revoke', ban.id, { ip: ban.ip, reason: ban.reason });
    const published = await redis.publish({
      type: 'unban',
      ban_id: ban.id,
      ip: ban.ip,
      reason: ban.reason,
      source: 'manual',
      banned_by: req.user.sub,
    });
    if (!published) {
      console.error('Unban recorded but not published to Redis', { ban_id: ban.id });
    }
    const commanded = await redis.publishCommand({
      type: 'unban',
      ban_id: ban.id,
      ip: ban.ip,
      reason: ban.reason,
      dry_run: ban.dry_run,
      source: 'manual',
    });
    if (!commanded) {
      console.error('Unban recorded but the agent command was not published', {
        ban_id: ban.id,
      });
    }
    return res.json({ ban: publicBan(ban) });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
