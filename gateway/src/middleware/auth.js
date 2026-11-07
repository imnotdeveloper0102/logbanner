const jwt = require('jsonwebtoken');
const config = require('../config');
const { unauthorized, forbidden } = require('../errors');

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return next(unauthorized());
  }
  try {
    req.user = jwt.verify(token, config.jwtAccessSecret);
    return next();
  } catch {
    return next(unauthorized('Access token is invalid or expired'));
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return next(forbidden('Admin role is required'));
    }
    return next();
  };
}

// Shared secret for service-to-service calls (agent, admin-service).
function requireServiceToken(req, res, next) {
  if (!config.serviceToken) {
    return next(forbidden('Service token is not configured'));
  }
  const token = req.headers['x-service-token'];
  if (!token || token !== config.serviceToken) {
    return next(forbidden('Invalid service token'));
  }
  return next();
}

module.exports = { requireAuth, requireRole, requireServiceToken };
