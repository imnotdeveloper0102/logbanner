const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const config = require('./config');

const ACCESS_TTL = '15m';
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function signAccess(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, config.jwtAccessSecret, {
    expiresIn: ACCESS_TTL,
  });
}

function newRefreshToken() {
  return crypto.randomBytes(48).toString('base64url');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function refreshExpiry() {
  return new Date(Date.now() + REFRESH_TTL_MS);
}

module.exports = {
  signAccess,
  newRefreshToken,
  hashToken,
  refreshExpiry,
};
