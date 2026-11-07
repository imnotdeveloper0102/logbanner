const express = require('express');
const config = require('../config');
const { requireAuth } = require('../middleware/auth');
const { badRequest } = require('../errors');

const router = express.Router();

// Thin proxy to the PHP admin service (stage 7). The browser cannot
// call the admin service directly — it has no JWT, only the shared
// service token — so the gateway forwards the logged-in user's JWT
// check here and the service token plus the user's id/role there
// (the admin service audits list/report actions under that user).
// Query params are validated here so a bad date is a 400 from the
// gateway, not a confusing pass-through.
function isDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

async function proxyReport(req, res, next, kind) {
  try {
    const format = req.query.format || 'json';
    if (!['json', 'csv', 'pdf'].includes(format)) {
      return next(badRequest('format must be json, csv, or pdf'));
    }
    const param = kind === 'daily' ? 'date' : 'start';
    if (req.query[param] !== undefined && !isDate(req.query[param])) {
      return next(badRequest(`${param} must be YYYY-MM-DD`));
    }
    const search = new URLSearchParams();
    if (req.query[param]) {
      search.set(param, req.query[param]);
    }
    search.set('format', format);
    let upstream;
    try {
      upstream = await fetch(`${config.adminServiceUrl}/api/reports/${kind}?${search}`, {
        headers: {
          'X-Service-Token': config.serviceToken,
          'X-User-Id': req.user.sub,
          'X-User-Role': req.user.role,
        },
      });
    } catch (err) {
      console.error('Report proxy: admin service unreachable', err);
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
  } catch (err) {
    return next(err);
  }
}

router.get('/daily', requireAuth, (req, res, next) => proxyReport(req, res, next, 'daily'));
router.get('/weekly', requireAuth, (req, res, next) => proxyReport(req, res, next, 'weekly'));

module.exports = router;
