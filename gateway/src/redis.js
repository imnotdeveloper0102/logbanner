// Redis clients for the gateway. Two clients are needed because a
// node-redis client in subscriber mode cannot publish: one publishes
// manual ban/unban events, the other subscribes to logbanner:events
// and feeds the WebSocket broadcaster. Both connect lazily so a
// Redis outage never stops the gateway starting; publish failures
// are logged by the caller and never fail the HTTP request that
// already wrote the row.
const { createClient } = require('redis');
const config = require('./config');

const CHANNEL = 'logbanner:events';
// Commands the agent listens for: manual bans/unbans from the
// gateway. Kept off the events channel so the WebSocket feed never
// shows a command as an event, and so the agent can subscribe to
// commands without receiving its own detections back.
const COMMANDS_CHANNEL = 'logbanner:commands';

let publisher = null;
let publisherReady = null;
let subscriber = null;

function newClient() {
  const client = createClient({ url: config.redisUrl });
  client.on('error', (err) => {
    console.error('Redis client error', err.message);
  });
  return client;
}

async function getPublisher() {
  if (!publisher) {
    publisher = newClient();
    publisherReady = publisher.connect().catch((err) => {
      console.error('Redis publisher could not connect', err.message);
      publisher = null;
      publisherReady = null;
      throw err;
    });
  }
  await publisherReady;
  return publisher;
}

async function publish(event) {
  let client;
  try {
    client = await getPublisher();
  } catch {
    return false;
  }
  try {
    await client.publish(CHANNEL, JSON.stringify(event));
    return true;
  } catch (err) {
    console.error('Redis publish failed', err.message);
    return false;
  }
}

// subscribe returns the subscriber client after its first successful
// subscribe, or null when Redis is unreachable (the caller retries
// on its own schedule instead of crashing the gateway).
async function subscribe(onMessage) {
  if (subscriber) {
    return subscriber;
  }
  const client = newClient();
  try {
    await client.connect();
    await client.subscribe(CHANNEL, (message) => {
      let event;
      try {
        event = JSON.parse(message);
      } catch {
        console.error('Skipping malformed message on logbanner:events');
        return;
      }
      if (!event || typeof event !== 'object' || typeof event.type !== 'string') {
        console.error('Skipping message without a type on logbanner:events');
        return;
      }
      onMessage(event);
    });
  } catch (err) {
    console.error('Redis subscriber could not connect', err.message);
    try {
      await client.destroy();
    } catch {
      // Already closed or never connected; nothing to clean up.
    }
    return null;
  }
  subscriber = client;
  return client;
}

async function close() {
  const clients = [publisher, subscriber].filter(Boolean);
  publisher = null;
  subscriber = null;
  publisherReady = null;
  await Promise.allSettled(clients.map((client) => client.quit().catch(() => client.destroy())));
}

// publishCommand sends a command to the agent (manual ban/unban).
// Like publish, a Redis failure is logged and reported as false;
// the database row is already written by the caller, so the ban
// is recorded even if the command never reaches the agent.
async function publishCommand(event) {
  let client;
  try {
    client = await getPublisher();
  } catch {
    return false;
  }
  try {
    await client.publish(COMMANDS_CHANNEL, JSON.stringify(event));
    return true;
  } catch (err) {
    console.error('Redis command publish failed', err.message);
    return false;
  }
}

module.exports = { CHANNEL, COMMANDS_CHANNEL, publish, publishCommand, subscribe, close };
