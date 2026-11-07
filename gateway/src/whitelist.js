// Hard whitelist for manual bans, mirroring the agent's
// internal/whitelist package: loopback is always whitelisted, and the
// default ranges are the RFC1918 private ranges from the agent's
// config defaults (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
// The two lists must match: if the agent config file at
// AGENT_CONFIG_PATH is readable and sets a whitelist, its entries
// replace the defaults here (an explicit empty list whitelists
// nothing extra, exactly as the agent treats it). A bad entry in
// that file is ignored with a warning rather than crashing the
// gateway, because the agent already refuses to start on a bad
// whitelist; the gateway log says which entries were dropped.
const fs = require('node:fs');
const net = require('node:net');
const config = require('./config');
const db = require('./db');

const DEFAULT_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

function ipToBigInt(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    return ip.split('.').reduce((acc, octet) => (acc << 8n) | BigInt(octet), 0n);
  }
  // IPv6: expand the :: shorthand, then fold 16 bytes into a BigInt.
  const [head, tail = ''] = ip.split('::');
  const headParts = head ? head.split(':') : [];
  const tailParts = tail ? tail.split(':') : [];
  const missing = 8 - headParts.length - tailParts.length;
  const parts = [...headParts, ...Array(missing).fill('0'), ...tailParts];
  return parts.reduce((acc, part) => (acc << 16n) | BigInt(parseInt(part, 16)), 0n);
}

function parseRange(entry) {
  if (net.isIP(entry)) {
    const bits = net.isIP(entry) === 4 ? 32n : 128n;
    return { network: ipToBigInt(entry), mask: (1n << bits) - 1n, bits };
  }
  const slash = entry.indexOf('/');
  if (slash === -1) {
    return null;
  }
  const addr = entry.slice(0, slash);
  const prefix = Number(entry.slice(slash + 1));
  const version = net.isIP(addr);
  if (!version || !Number.isInteger(prefix)) {
    return null;
  }
  const bits = version === 4 ? 32 : 128;
  if (prefix < 0 || prefix > bits) {
    return null;
  }
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
  return { network: ipToBigInt(addr) & mask, mask, bits: BigInt(bits) };
}

function readAgentWhitelist() {
  if (!config.agentConfigPath) {
    return null;
  }
  let text;
  try {
    text = fs.readFileSync(config.agentConfigPath, 'utf8');
  } catch {
    return null;
  }
  // Minimal YAML read: only the top-level `whitelist:` list of
  // `- <entry>` lines is needed; anything else is left to the agent.
  const lines = text.split('\n');
  const start = lines.findIndex((line) => /^whitelist:\s*$/.test(line));
  if (start === -1) {
    return null;
  }
  const entries = [];
  for (const line of lines.slice(start + 1)) {
    const match = line.match(/^\s+-\s+(\S+)\s*$/);
    if (match) {
      entries.push(match[1]);
      continue;
    }
    if (/^\S/.test(line) && line.trim() !== '') {
      break;
    }
  }
  return entries;
}

function buildList() {
  const configured = readAgentWhitelist();
  const entries = configured === null ? DEFAULT_RANGES : configured;
  const ranges = [];
  for (const entry of entries) {
    const range = parseRange(entry);
    if (!range) {
      console.warn(`Ignoring invalid whitelist entry ${entry}`);
      continue;
    }
    ranges.push(range);
  }
  return ranges;
}

const ranges = buildList();

function isWhitelisted(ip) {
  if (!net.isIP(ip)) {
    return false;
  }
  // Loopback is whitelisted unconditionally, as in the agent.
  if (ip === '::1' || ip.startsWith('127.')) {
    return true;
  }
  const value = ipToBigInt(ip);
  return ranges.some((range) => (value & range.mask) === range.network);
}

// isWhitelistedAny is the full check: the agent-config ranges above
// plus any whitelist entry an admin added to manual_lists (via
// POST /api/lists or the admin service). The manual entries are
// read from the database and matched in JS with the same range
// logic, so a malformed stored value is skipped with a warning
// instead of breaking the query. The agent enforces the same
// manual list on its own ban paths; the two must agree, and a
// mismatch means the agent has not picked up the list yet.
async function isWhitelistedAny(ip) {
  if (isWhitelisted(ip)) {
    return true;
  }
  let rows;
  try {
    ({ rows } = await db.query("SELECT value FROM manual_lists WHERE kind = 'whitelist'"));
  } catch (err) {
    console.error('Failed to read manual whitelist, using config list only', err.message);
    return false;
  }
  const value = ipToBigInt(ip);
  for (const row of rows) {
    const range = parseRange(row.value);
    if (!range) {
      console.warn(`Ignoring invalid manual whitelist entry ${row.value}`);
      continue;
    }
    if ((value & range.mask) === range.network) {
      return true;
    }
  }
  return false;
}

module.exports = { isWhitelisted, isWhitelistedAny, DEFAULT_RANGES };
