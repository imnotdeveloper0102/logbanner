// GeoIP lookup behind a small interface, backed by a MaxMind
// GeoLite2 .mmdb file when one is configured and present.
//
// No database file ships with the project: GeoLite2 is free but
// needs a MaxMind account and licence key to download (see the
// README stage 6 section). When GEOIP_DB_PATH is unset, points at
// a missing file, or the file cannot be opened, every lookup
// honestly returns country "unknown" — locations are never
// invented, and no download is attempted here because that would
// need a licence key the operator has not provided.
const fs = require('node:fs');
const net = require('node:net');
const config = require('./config');

let readerPromise = null;
let readerFailed = false;

function dbPath() {
  return config.geoipDbPath || '';
}

function hasDatabase() {
  const path = dbPath();
  if (!path) {
    return false;
  }
  try {
    return fs.statSync(path).isFile();
  } catch {
    return false;
  }
}

async function getReader() {
  if (readerPromise) {
    return readerPromise;
  }
  if (readerFailed || !hasDatabase()) {
    return null;
  }
  readerPromise = (async () => {
    try {
      const maxmind = require('maxmind');
      return await maxmind.open(dbPath());
    } catch (err) {
      readerFailed = true;
      readerPromise = null;
      console.error(
        `GeoIP database at ${dbPath()} could not be opened, lookups return unknown`,
        err.message,
      );
      return null;
    }
  })();
  return readerPromise;
}

// lookup returns { country, city, subdivision, latitude, longitude }
// with country "unknown" and the rest null when there is no database
// or no record for the IP. An invalid IP returns null.
async function lookup(ip) {
  if (!net.isIP(ip)) {
    return null;
  }
  const reader = await getReader();
  if (!reader) {
    return { country: 'unknown', city: null, subdivision: null, latitude: null, longitude: null };
  }
  let record = null;
  try {
    record = reader.get(ip);
  } catch (err) {
    console.error('GeoIP lookup failed', err.message);
    return { country: 'unknown', city: null, subdivision: null, latitude: null, longitude: null };
  }
  if (!record) {
    return { country: 'unknown', city: null, subdivision: null, latitude: null, longitude: null };
  }
  return {
    country: (record.country && record.country.iso_code) || 'unknown',
    city: (record.city && record.city.names && record.city.names.en) || null,
    subdivision:
      (record.subdivisions &&
        record.subdivisions[0] &&
        record.subdivisions[0].names &&
        record.subdivisions[0].names.en) ||
      null,
    latitude: record.location ? (record.location.latitude ?? null) : null,
    longitude: record.location ? (record.location.longitude ?? null) : null,
  };
}

module.exports = { lookup, hasDatabase, dbPath };
