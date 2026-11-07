// Log sources the agent is tailing, read from the live agent
// config file at AGENT_CONFIG_PATH, with live parse metrics from
// the agent's status file when AGENT_STATE_DIR is configured.
//
// The agent writes <state_dir>/sources-status.json on every 30s
// summary tick: per-source lines_read/parsed/unparsable plus an
// updated_at timestamp. The gateway never invents counts: a source
// with no fresh status file reports status "unavailable" and null
// counts, and a file older than 120s is "stale" — the agent may
// have stopped. When the config file cannot be read the response
// is an empty list with a note saying so.
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const config = require('../config');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
const STALE_AFTER_MS = 120 * 1000;

function readSources() {
  if (!config.agentConfigPath) {
    return {
      sources: [],
      note: 'AGENT_CONFIG_PATH is not set, so the gateway cannot read the agent config.',
    };
  }
  let text;
  try {
    text = fs.readFileSync(config.agentConfigPath, 'utf8');
  } catch {
    return {
      sources: [],
      note: `Agent config not found at ${config.agentConfigPath}; no live sources available.`,
    };
  }
  // Minimal YAML read: only the top-level `sources:` list of
  // `- path: ...` / `format: ...` entries is needed.
  const sources = [];
  const lines = text.split('\n');
  const start = lines.findIndex((line) => /^sources:\s*$/.test(line));
  if (start === -1) {
    return { sources, note: 'Agent config has no sources list.' };
  }
  let current = null;
  for (const line of lines.slice(start + 1)) {
    const item = line.match(/^\s+-\s+path:\s*(\S+)\s*$/);
    if (item) {
      current = { path: item[1], format: '' };
      sources.push(current);
      continue;
    }
    const format = line.match(/^\s+format:\s*(\S+)\s*$/);
    if (format && current) {
      current.format = format[1];
      continue;
    }
    if (/^\S/.test(line) && line.trim() !== '') {
      break;
    }
  }
  return { sources, note: null };
}

function readStatus() {
  if (!config.agentStateDir) {
    return {
      metrics: null,
      note: 'AGENT_STATE_DIR is not set, so live parse metrics are unavailable.',
    };
  }
  const file = path.join(config.agentStateDir, 'sources-status.json');
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return {
      metrics: null,
      note: `Agent status file not found at ${file}; the agent has not reported yet.`,
    };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { metrics: null, note: `Agent status file at ${file} is not valid JSON.` };
  }
  return { metrics: parsed, note: null };
}

router.get('/', requireAuth, (req, res) => {
  const { sources, note: configNote } = readSources();
  const { metrics, note: statusNote } = readStatus();
  const now = Date.now();
  const byPath = new Map();
  if (metrics && metrics.sources) {
    for (const entry of metrics.sources) {
      byPath.set(entry.path, entry);
    }
  }
  const fresh =
    metrics && metrics.updated_at
      ? now - new Date(metrics.updated_at).getTime() < STALE_AFTER_MS
      : false;
  const merged = sources.map((source) => {
    const entry = byPath.get(source.path);
    if (!entry) {
      return {
        ...source,
        status: 'unavailable',
        lines_read: null,
        parsed: null,
        unparsable: null,
        last_reported_at: null,
      };
    }
    return {
      ...source,
      status: fresh ? 'reporting' : 'stale',
      lines_read: entry.lines_read ?? null,
      parsed: entry.parsed ?? null,
      unparsable: entry.unparsable ?? null,
      last_reported_at: metrics.updated_at,
    };
  });
  const note = configNote || statusNote;
  return res.json({
    sources: merged,
    note,
    agent_started_at: (metrics && metrics.agent_started_at) || null,
  });
});

module.exports = router;
