const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { signAccess, newRefreshToken, hashToken, refreshExpiry } = require('../auth');
const { registerSchema, loginSchema } = require('../validate');
const { unauthorized, conflict } = require('../errors');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const REFRESH_COOKIE = 'logbanner_refresh';
const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  path: '/api/auth',
  maxAge: 30 * 24 * 60 * 60 * 1000,
};

function publicUser(user) {
  return { id: user.id, email: user.email, role: user.role, created_at: user.created_at };
}

async function issueRefreshToken(res, userId) {
  const token = newRefreshToken();
  await db.query(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [userId, hashToken(token), refreshExpiry()],
  );
  res.cookie(REFRESH_COOKIE, token, cookieOptions);
}

// Registration always creates a viewer. An admin promotes accounts.
router.post('/register', async (req, res, next) => {
  try {
    const { email, password } = registerSchema.parse(req.body);
    const passwordHash = await bcrypt.hash(password, 12);
    const { rows } = await db.query(
      'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role, created_at',
      [email, passwordHash, 'viewer'],
    );
    const user = rows[0];
    await issueRefreshToken(res, user.id);
    return res.status(201).json({ accessToken: signAccess(user), user: publicUser(user) });
  } catch (err) {
    if (err && err.code === '23505') {
      return next(conflict('Email is already registered'));
    }
    return next(err);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = loginSchema.parse(req.body);
    const { rows } = await db.query('SELECT * FROM users WHERE lower(email) = lower($1)', [email]);
    const user = rows[0];
    if (!user) {
      return next(unauthorized('Email or password is incorrect'));
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return next(unauthorized('Email or password is incorrect'));
    }
    await issueRefreshToken(res, user.id);
    return res.json({ accessToken: signAccess(user), user: publicUser(user) });
  } catch (err) {
    return next(err);
  }
});

router.post('/refresh', async (req, res, next) => {
  try {
    const token = req.cookies && req.cookies[REFRESH_COOKIE];
    if (!token) {
      return next(unauthorized('Refresh token is missing'));
    }
    const { rows } = await db.query(
      `SELECT rt.id, rt.user_id, rt.expires_at, u.email, u.role, u.created_at
         FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
        WHERE rt.token_hash = $1 AND rt.revoked_at IS NULL`,
      [hashToken(token)],
    );
    const record = rows[0];
    if (!record || new Date(record.expires_at) <= new Date()) {
      return next(unauthorized('Refresh token is invalid or expired'));
    }
    await db.query('UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1', [record.id]);
    const user = {
      id: record.user_id,
      email: record.email,
      role: record.role,
      created_at: record.created_at,
    };
    await issueRefreshToken(res, user.id);
    return res.json({ accessToken: signAccess(user), user: publicUser(user) });
  } catch (err) {
    return next(err);
  }
});

router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    const token = req.cookies && req.cookies[REFRESH_COOKIE];
    if (token) {
      await db.query('UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1', [
        hashToken(token),
      ]);
    }
    res.clearCookie(REFRESH_COOKIE, { path: '/api/auth' });
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
});

router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await db.query('SELECT id, email, role, created_at FROM users WHERE id = $1', [
      req.user.sub,
    ]);
    if (rows.length === 0) {
      return next(unauthorized('Account no longer exists'));
    }
    return res.json({ user: rows[0] });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
