const express = require('express');
const net = require('node:net');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { eventsQuerySchema } = require('../validate');
const { badRequest } = require('../errors');

const router = express.Router();

// Paginated detections, newest first, with the rule name joined in.
// The raw JSONB evidence is not returned here; the detail view that
// needs it lands with the IP detail page in stage 6.
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const query = eventsQuerySchema.parse(req.query);
    if (query.ip && !net.isIP(query.ip)) {
      return next(badRequest('ip must be a valid IP address'));
    }
    const conditions = [];
    const params = [];
    if (query.rule) {
      params.push(query.rule);
      conditions.push(`r.name = $${params.length}`);
    }
    if (query.ip) {
      params.push(query.ip);
      conditions.push(`e.ip = $${params.length}::inet`);
    }
    if (query.severity) {
      params.push(query.severity);
      conditions.push(`e.severity = $${params.length}`);
    }
    if (query.since) {
      params.push(query.since);
      conditions.push(`e.occurred_at >= $${params.length}::timestamptz`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const totalParams = [...params];
    const { rows: countRows } = await db.query(
      `SELECT count(*) AS total FROM events e LEFT JOIN rules r ON r.id = e.rule_id ${where}`,
      totalParams,
    );
    const offset = (query.page - 1) * query.limit;
    params.push(query.limit, offset);
    const { rows } = await db.query(
      `SELECT e.id, e.occurred_at, e.source, host(e.ip) AS ip, e.severity, e.message,
              r.name AS rule_name
         FROM events e LEFT JOIN rules r ON r.id = e.rule_id
        ${where}
        ORDER BY e.occurred_at DESC, e.created_at DESC
        LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );
    return res.json({
      events: rows,
      page: query.page,
      limit: query.limit,
      total: Number(countRows[0].total),
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
