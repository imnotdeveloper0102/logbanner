const express = require('express');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Circuit breaker state (stage 8). The agent persists every
// breaker transition — trip and re-arm — as a critical events row
// with source 'agent' and raw.type 'circuit_breaker', and
// publishes the same payload on Redis logbanner:events. This
// endpoint derives the state from the latest such row in the
// database, so it reports what the agent actually did, never a
// guessed or cached state. With no breaker event recorded yet the
// breaker has never tripped: open is false and last_event_at is
// null, and the dashboard says so instead of inventing a history.
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT occurred_at, message, raw
         FROM events
        WHERE source = 'agent' AND raw ->> 'type' = 'circuit_breaker'
        ORDER BY occurred_at DESC LIMIT 1`,
    );
    if (rows.length === 0) {
      return res.json({
        open: false,
        state: 'closed',
        bans_in_window: null,
        max_bans: null,
        window_seconds: null,
        opened_at: null,
        last_event_at: null,
        message: 'No circuit-breaker events recorded yet',
      });
    }
    const row = rows[0];
    const raw = row.raw || {};
    return res.json({
      open: raw.state === 'open',
      state: raw.state === 'open' ? 'open' : 'closed',
      bans_in_window: raw.bans_in_window ?? null,
      max_bans: raw.max_bans ?? null,
      window_seconds: raw.window_seconds ?? null,
      opened_at: raw.opened_at || null,
      last_event_at: row.occurred_at,
      message: row.message,
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
