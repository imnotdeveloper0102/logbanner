const express = require('express');
const net = require('node:net');
const db = require('../db');
const config = require('../config');
const { requireAuth, requireRole } = require('../middleware/auth');
const { listCreateSchema } = require('../validate');
const { badRequest, conflict } = require('../errors');

const router = express.Router();

// Manual whitelist/blacklist entries (manual_lists). This is the
// gateway's own endpoint for the list; the admin service has the
// same table behind its service-token API, and both write the same
// rows. A whitelist entry here is enforced: the gateway refuses
// manual bans for it, the IP detail page reports it, and the agent
// checks the same table before applying a detection ban or a
// manual-ban command. A value is one IP or one CIDR range.
function parseValue(value) {
  if (net.isIP(value)) {
    return true;
  }
  const slash = value.indexOf('/');
  if (slash === -1) {
    return false;
  }
  const addr = value.slice(0, slash);
  const prefix = Number(value.slice(slash + 1));
  if (!net.isIP(addr) || !Number.isInteger(prefix)) {
    return false;
  }
  const bits = net.isIP(addr) === 4 ? 32 : 128;
  return prefix >= 0 && prefix <= bits;
}

router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT id, kind, value, reason, created_by, created_at
         FROM manual_lists ORDER BY kind, created_at DESC`,
    );
    return res.json({ lists: rows });
  } catch (err) {
    return next(err);
  }
});

router.post('/', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const body = listCreateSchema.parse(req.body);
    if (!parseValue(body.value)) {
      return next(badRequest('value must be a valid IP address or CIDR range'));
    }
    let row;
    try {
      ({
        rows: [row],
      } = await db.query(
        `INSERT INTO manual_lists (kind, value, reason, created_by)
         VALUES ($1, $2, $3, $4::uuid)
         RETURNING id, kind, value, reason, created_by, created_at`,
        [body.kind, body.value, body.reason, req.user.sub],
      ));
    } catch (err) {
      if (err.code === '23505') {
        return next(conflict('That entry already exists'));
      }
      throw err;
    }
    await db.query(
      'INSERT INTO audit_logs (actor_id, action, target_type, target_id, details) VALUES ($1, $2, $3, $4, $5::jsonb)',
      [
        req.user.sub,
        'list.create',
        'manual_list',
        row.id,
        JSON.stringify({ kind: row.kind, value: row.value, reason: row.reason }),
      ],
    );
    return res.status(201).json({ entry: row });
  } catch (err) {
    return next(err);
  }
});

// The admin service owns delete/import/export for manual_lists
// (stage 7); the gateway proxies them so the frontend keeps one
// base URL and one login. The user's id/role are forwarded for the
// admin service's audit trail, alongside the service token.
async function proxyAdmin(req, res, next, path, init) {
  let upstream;
  try {
    upstream = await fetch(`${config.adminServiceUrl}${path}`, {
      ...init,
      headers: {
        'X-Service-Token': config.serviceToken,
        'X-User-Id': req.user.sub,
        'X-User-Role': req.user.role,
        ...(init.headers || {}),
      },
    });
  } catch (err) {
    console.error('Lists proxy: admin service unreachable', err);
    return res.status(502).json({ error: { message: 'Admin service is unreachable' } });
  }
  const contentType = upstream.headers.get('content-type');
  if (contentType) {
    res.set('Content-Type', contentType);
  }
  const disposition = upstream.headers.get('content-disposition');
  if (disposition) {
    res.set('Content-Disposition', disposition);
  }
  const body = Buffer.from(await upstream.arrayBuffer());
  return res.status(upstream.status).send(body);
}

router.delete('/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    return await proxyAdmin(req, res, next, `/api/lists/${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
    });
  } catch (err) {
    return next(err);
  }
});

router.get('/export', requireAuth, async (req, res, next) => {
  try {
    const kind = req.query.kind;
    if (kind !== undefined && kind !== 'whitelist' && kind !== 'blacklist') {
      return next(badRequest('kind must be whitelist or blacklist'));
    }
    const search = kind ? `?kind=${encodeURIComponent(kind)}` : '';
    return await proxyAdmin(req, res, next, `/api/lists/export${search}`, { method: 'GET' });
  } catch (err) {
    return next(err);
  }
});

router.post(
  '/import',
  requireAuth,
  requireRole('admin'),
  express.text({ type: ['text/plain', 'text/csv'], limit: '1mb' }),
  async (req, res, next) => {
    try {
      const kind = req.query.kind;
      if (kind !== 'whitelist' && kind !== 'blacklist') {
        return next(badRequest('kind query parameter must be whitelist or blacklist'));
      }
      if (typeof req.body !== 'string') {
        return next(badRequest('Import body must be plain text or CSV, one entry per line'));
      }
      return await proxyAdmin(req, res, next, `/api/lists/import?kind=${kind}`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        body: req.body,
      });
    } catch (err) {
      return next(err);
    }
  },
);

module.exports = router;
