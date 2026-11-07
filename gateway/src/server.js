const http = require('node:http');
const app = require('./app');
const config = require('./config');
const db = require('./db');
const redis = require('./redis');
const live = require('./live');

const server = http.createServer(app);
const ws = live.attach(server);

server.listen(config.port, () => {
  console.log(`logbanner gateway listening on ${config.port}`);
});

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down`);
  ws.close();
  server.close(() => {
    Promise.allSettled([db.close(), redis.close()])
      .then(() => process.exit(0))
      .catch((err) => {
        console.error('Error closing connections', err);
        process.exit(1);
      });
  });
  setTimeout(() => process.exit(1), 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
