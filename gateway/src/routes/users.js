const express = require('express');
const db = require('../db');
const { roleSchema } = require('../validate');
const { requireAuth, requireRole } = require('../middleware/auth');
const { notFound } = require('../errors');

const router = express.Router();

router.use(requireAuth, requireRole('admin'));

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      'SELECT id, email, role, created_at FROM users ORDER BY created_at ASC',
    );
    return res.json({ users: rows });
  } catch (err) {
    return next(err);
  }
});

router.patch('/:id/role', async (req, res, next) => {
  try {
    const { role } = roleSchema.parse(req.body);
    const { rows } = await db.query(
      'UPDATE users SET role = $1, updated_at = now() WHERE id = $2 RETURNING id, email, role, created_at',
      [role, req.params.id],
    );
    if (rows.length === 0) {
      return next(notFound('User not found'));
    }
    return res.json({ user: rows[0] });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
