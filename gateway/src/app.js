const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('./config');
const db = require('./db');
const errorHandler = require('./middleware/errorHandler');
const authRoutes = require('./routes/auth');
const statsRoutes = require('./routes/stats');
const usersRoutes = require('./routes/users');
const eventsRoutes = require('./routes/events');
const bansRoutes = require('./routes/bans');
const rulesRoutes = require('./routes/rules');
const sourcesRoutes = require('./routes/sources');
const ipsRoutes = require('./routes/ips');
const geoRoutes = require('./routes/geo');
const listsRoutes = require('./routes/lists');
const reportsRoutes = require('./routes/reports');
const circuitBreakerRoutes = require('./routes/circuit-breaker');

const app = express();

app.use(helmet());
app.use(cors({ origin: config.corsOrigin, credentials: true }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
  }),
);

app.get(['/health', '/api/health'], async (req, res) => {
  try {
    await db.query('SELECT 1');
    return res.json({ status: 'ok' });
  } catch (err) {
    console.error('Health check failed', err);
    return res.status(503).json({ status: 'degraded', detail: 'Database is unreachable' });
  }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: { message: 'Too many login attempts, try again later' } },
});
app.use('/api/auth/login', loginLimiter);

app.use('/api/auth', authRoutes);
app.use('/api/stats', statsRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/events', eventsRoutes);
app.use('/api/bans', bansRoutes);
app.use('/api/rules', rulesRoutes);
app.use('/api/sources', sourcesRoutes);
app.use('/api/ips', ipsRoutes);
app.use('/api/geo', geoRoutes);
app.use('/api/lists', listsRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/circuit-breaker', circuitBreakerRoutes);

app.use((req, res) => {
  res.status(404).json({ error: { message: 'Route not found' } });
});

app.use(errorHandler);

module.exports = app;
