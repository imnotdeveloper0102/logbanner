const express = require('express');
const db = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { rulePatchSchema } = require('../validate');
const { badRequest, notFound } = require('../errors');

const router = express.Router();

function publicRule(row) {
  return {
    id: row.id,
    name: row.name,
    source: row.source,
    pattern: row.pattern,
    threshold: row.threshold,
    window_seconds: row.window_seconds,
    ban_seconds: row.ban_seconds,
    action: row.action,
    enabled: row.enabled,
    escalation: row.escalation,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT id, name, source, pattern, threshold, window_seconds, ban_seconds,
              action, enabled, escalation, created_at, updated_at
         FROM rules ORDER BY name ASC`,
    );
    return res.json({ rules: rows.map(publicRule) });
  } catch (err) {
    return next(err);
  }
});

// validatePattern compiles the pattern the way the agent will:
// `*` matches everything, `status=` takes a code or class, `ua:`
// takes a regex matched against the User-Agent, and anything else
// is a regex matched against "METHOD PATH" (or the raw line for
// ssh). The compile attempt is the syntax check before save: a
// bad pattern is a 400 carrying the concrete error, never a row
// the agent would refuse to load.
function validatePattern(pattern) {
  if (pattern === '*') {
    return null;
  }
  if (pattern.startsWith('status=')) {
    const spec = pattern.slice('status='.length);
    if (/^[1-9]xx$/.test(spec)) {
      return null;
    }
    const code = Number(spec);
    if (!/^\d{3}$/.test(spec) || code < 100 || code > 999) {
      return 'invalid status pattern: want status=NNN or status=Nxx';
    }
    return null;
  }
  const regexText = pattern.startsWith('ua:') ? pattern.slice('ua:'.length) : pattern;
  try {
    new RegExp(regexText);
  } catch (err) {
    return `invalid pattern: ${err.message}`;
  }
  return null;
}

// PATCH /api/rules/:id (admin only). Edits threshold,
// window_seconds, ban_seconds, action, escalation, pattern, and
// enabled through this one endpoint. The rules table is the single
// source of truth: the agent loads its active rules from the
// database (the YAML file only seeds rules that do not exist yet),
// so an edit here is what the agent runs after its next SIGHUP or
// restart — the response says so, and the UI repeats it. The change
// is audit-logged with the old and new values.
router.patch('/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const body = rulePatchSchema.parse(req.body);
    const { rows: existing } = await db.query(
      `SELECT id, name, source, pattern, threshold, window_seconds, ban_seconds,
              action, enabled, escalation, created_at, updated_at
         FROM rules WHERE id = $1::uuid`,
      [req.params.id],
    );
    if (existing.length === 0) {
      return next(notFound('Rule not found'));
    }
    const old = existing[0];
    if (body.pattern !== undefined) {
      const error = validatePattern(body.pattern);
      if (error) {
        return next(badRequest(error));
      }
    }
    const nextRow = { ...old, ...body };
    const { rows } = await db.query(
      `UPDATE rules
          SET threshold = $1, window_seconds = $2, ban_seconds = $3,
              action = $4, enabled = $5, pattern = $6, escalation = $7::jsonb,
              updated_at = now()
        WHERE id = $8::uuid
        RETURNING id, name, source, pattern, threshold, window_seconds, ban_seconds,
                  action, enabled, escalation, created_at, updated_at`,
      [
        nextRow.threshold,
        nextRow.window_seconds,
        nextRow.ban_seconds,
        nextRow.action,
        nextRow.enabled,
        nextRow.pattern,
        JSON.stringify(nextRow.escalation ?? []),
        req.params.id,
      ],
    );
    const updated = rows[0];
    const changed = {};
    for (const key of Object.keys(body)) {
      changed[key] = { old: old[key], new: updated[key] };
    }
    await db.query(
      'INSERT INTO audit_logs (actor_id, action, target_type, target_id, details) VALUES ($1, $2, $3, $4, $5::jsonb)',
      [
        req.user.sub,
        'rule.update',
        'rule',
        updated.id,
        JSON.stringify({ rule: updated.name, changed }),
      ],
    );
    return res.json({
      rule: publicRule(updated),
      takes_effect: 'on the next agent reload (SIGHUP) or restart',
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
