require('dotenv').config();

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

const config = {
  port: Number(process.env.PORT || 3001),
  databaseUrl: required('DATABASE_URL'),
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  jwtAccessSecret: required('JWT_ACCESS_SECRET'),
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  serviceToken: process.env.SERVICE_TOKEN || '',
  adminEmail: process.env.ADMIN_EMAIL || '',
  adminPassword: process.env.ADMIN_PASSWORD || '',
  // Same flag the agent uses, and it defaults the same way (true):
  // a manual ban in dry-run mode is recorded in the database and
  // published, but never applied to the firewall.
  dryRun: process.env.AGENT_DRY_RUN !== 'false',
  // Path of the live agent config file, when the agent runs on this
  // host. Used by GET /api/sources; unset or unreadable means the
  // gateway honestly reports no sources instead of inventing any.
  agentConfigPath: process.env.AGENT_CONFIG_PATH || '',
  // Directory the agent writes its per-source status file into
  // (sources-status.json, one write per 30s summary tick). The
  // agent's state_dir; when unset, source metrics are unavailable.
  agentStateDir: process.env.AGENT_STATE_DIR || '',
  // Path of a MaxMind GeoLite2 .mmdb file (City or Country).
  // Unset or missing means every lookup returns "unknown"; see the
  // README stage 6 section for how to obtain one.
  geoipDbPath: process.env.GEOIP_DB_PATH || '',
  // Base URL of the PHP admin service (stage 7). The gateway
  // proxies report and list import/export calls there, forwarding
  // the service token plus the logged-in user's id/role for audit.
  adminServiceUrl: process.env.ADMIN_SERVICE_URL || 'http://localhost:8081',
};

module.exports = config;
