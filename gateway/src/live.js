// WebSocket live feed on /ws, attached to the same HTTP server as
// the REST API. Auth is a JWT access token in the `token` query
// parameter of the handshake URL; the browser cannot set an
// Authorization header on a WebSocket handshake, and the query
// parameter is the documented alternative. A missing or invalid
// token closes the connection with 4401. On connect the client
// gets a hello carrying the current counts, then every event the
// gateway receives on Redis channel logbanner:events, in real time.
const { WebSocket, WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');
const config = require('./config');
const db = require('./db');
const redis = require('./redis');

const clients = new Set();
let subscriberStarted = false;

async function currentCounts() {
  const { rows } = await db.query(
    `SELECT
       (SELECT count(*) FROM events WHERE occurred_at >= now() - interval '24 hours') AS events_24h,
       (SELECT count(*) FROM bans WHERE revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > now())) AS active_bans,
       (SELECT count(*) FROM rules WHERE enabled) AS rules_enabled,
       (SELECT count(*) FROM users) AS total_users`,
  );
  const row = rows[0];
  return {
    events24h: Number(row.events_24h),
    activeBans: Number(row.active_bans),
    rulesEnabled: Number(row.rules_enabled),
    totalUsers: Number(row.total_users),
  };
}

function broadcast(event) {
  const payload = JSON.stringify(event);
  for (const ws of clients) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  }
}

async function startSubscriber() {
  if (subscriberStarted) {
    return;
  }
  subscriberStarted = true;
  const client = await redis.subscribe((event) => broadcast(event));
  if (!client) {
    // Redis is down; retry in the background instead of crashing
    // the gateway. Clients stay connected and keep getting hellos
    // on reconnect; events resume when Redis comes back.
    subscriberStarted = false;
    setTimeout(() => {
      startSubscriber().catch((err) => {
        console.error('Redis resubscribe failed', err.message);
      });
    }, 5000).unref();
  }
}

function attach(server) {
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', async (ws, req) => {
    const url = new URL(req.url || '/ws', 'http://localhost');
    const token = url.searchParams.get('token');
    if (!token) {
      ws.close(4401, 'Access token is required');
      return;
    }
    let user;
    try {
      user = jwt.verify(token, config.jwtAccessSecret);
    } catch {
      ws.close(4401, 'Access token is invalid or expired');
      return;
    }
    clients.add(ws);
    ws.on('close', () => {
      clients.delete(ws);
    });
    ws.on('error', (err) => {
      console.error('WebSocket error', err.message);
      clients.delete(ws);
    });
    try {
      const counts = await currentCounts();
      ws.send(
        JSON.stringify({
          type: 'hello',
          user: { id: user.sub, email: user.email, role: user.role },
          counts,
        }),
      );
    } catch (err) {
      console.error('Failed to send hello to WebSocket client', err.message);
    }
  });

  startSubscriber().catch((err) => {
    console.error('Redis subscribe failed', err.message);
  });

  return {
    close() {
      for (const ws of clients) {
        ws.close();
      }
      clients.clear();
      wss.close();
    },
  };
}

module.exports = { attach };
