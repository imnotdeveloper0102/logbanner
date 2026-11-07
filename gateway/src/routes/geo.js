const express = require('express');
const net = require('node:net');
const { requireAuth } = require('../middleware/auth');
const { badRequest } = require('../errors');
const geoip = require('../geoip');

const router = express.Router();

// GET /api/geo/:ip — one lookup through the GeoIP interface.
// Without a configured GeoLite2 database the country is "unknown"
// and the rest is null; that is the honest answer, not a guess.
router.get('/:ip', requireAuth, async (req, res, next) => {
  try {
    const ip = req.params.ip;
    if (!net.isIP(ip)) {
      return next(badRequest('ip must be a valid IP address'));
    }
    const result = await geoip.lookup(ip);
    return res.json({ ip, ...result, database_available: geoip.hasDatabase() });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
