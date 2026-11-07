let accessToken = null;

export function setAccessToken(token) {
  accessToken = token;
}

export function getAccessToken() {
  return accessToken;
}

export function clearAccessToken() {
  accessToken = null;
}

async function request(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...(options.headers || {}),
    },
  });
  if (res.status === 204) {
    return null;
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const message =
      body && body.error && body.error.message
        ? body.error.message
        : `Request failed (${res.status})`;
    const error = new Error(message);
    error.status = res.status;
    error.details = body && body.error ? body.error.details : null;
    throw error;
  }
  return body;
}

// Retries once after refreshing the access token.
export async function api(path, options = {}) {
  try {
    return await request(path, options);
  } catch (err) {
    if (err.status !== 401 || options._retried) {
      throw err;
    }
    const refreshed = await request('/api/auth/refresh', { method: 'POST', _retried: true });
    setAccessToken(refreshed.accessToken);
    return request(path, { ...options, _retried: true });
  }
}

// Refreshes the access token via the rotating refresh cookie and
// returns the new token. The WebSocket handshake cannot use the
// retry flow above, so the live feed calls this directly when the
// socket closes with 4401.
export async function refreshAccessToken() {
  const refreshed = await request('/api/auth/refresh', { method: 'POST' });
  setAccessToken(refreshed.accessToken);
  return refreshed.accessToken;
}

export function loginRequest(email, password) {
  return request('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export function logoutRequest() {
  return request('/api/auth/logout', { method: 'POST' });
}

export function fetchMe() {
  return api('/api/auth/me');
}

export function fetchStats() {
  return api('/api/stats');
}

// Circuit breaker state (stage 8): open means the agent has
// paused automatic bans; closed means it is banning normally.
// The gateway derives it from the latest breaker event the agent
// persisted, so it is real state, never a guess.
export function fetchCircuitBreaker() {
  return api('/api/circuit-breaker');
}

function queryString(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

export function fetchEvents(params = {}) {
  return api(`/api/events${queryString(params)}`);
}

export function fetchBans(params = {}) {
  return api(`/api/bans${queryString(params)}`);
}

export function createBan({ ip, reason, durationSeconds = null, ruleId = null }) {
  return api('/api/bans', {
    method: 'POST',
    body: JSON.stringify({
      ip,
      reason,
      duration_seconds: durationSeconds,
      ...(ruleId ? { rule_id: ruleId } : {}),
    }),
  });
}

export function revokeBan(id) {
  return api(`/api/bans/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export function fetchRules() {
  return api('/api/rules');
}

// PATCH /api/rules/:id — threshold, window, ban length, action,
// escalation, pattern, enabled. The server validates the pattern
// with a real regex compile and returns 400 with the concrete
// error; the response also says the edit takes effect on the next
// agent reload (SIGHUP) or restart.
export function updateRule(id, body) {
  return api(`/api/rules/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export function fetchSources() {
  return api('/api/sources');
}

export function fetchIpDetail(ip, params = {}) {
  return api(`/api/ips/${encodeURIComponent(ip)}${queryString(params)}`);
}

export function fetchGeo(ip) {
  return api(`/api/geo/${encodeURIComponent(ip)}`);
}

export function fetchLists() {
  return api('/api/lists');
}

// Adds one IP or CIDR to the manual whitelist (or blacklist).
// Enforced by the gateway for manual bans and by the agent for
// detection bans and manual-ban commands.
export function addListEntry({ kind, value, reason = '' }) {
  return api('/api/lists', {
    method: 'POST',
    body: JSON.stringify({ kind, value, reason }),
  });
}

export function addWhitelist(ip, reason = '') {
  return addListEntry({ kind: 'whitelist', value: ip, reason });
}

export function deleteListEntry(id) {
  return api(`/api/lists/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

// Import list entries from plain text: one `value` or
// `value,reason` per line. kind is whitelist or blacklist.
export async function importListEntries(kind, text) {
  const res = await fetch(`/api/lists/import?kind=${encodeURIComponent(kind)}`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    },
    body: text,
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const error = new Error(
      body && body.error && body.error.message
        ? body.error.message
        : `Request failed (${res.status})`,
    );
    error.status = res.status;
    throw error;
  }
  return body;
}

// Daily/weekly reports from the admin service, via the gateway
// proxy. JSON for display; CSV/PDF download as a file.
export function fetchDailyReport(params = {}) {
  return api(`/api/reports/daily${queryString(params)}`);
}

export function fetchWeeklyReport(params = {}) {
  return api(`/api/reports/weekly${queryString(params)}`);
}

export async function downloadReport(kind, params = {}) {
  const query = queryString({ ...params, format: params.format || 'csv' });
  const res = await fetch(`/api/reports/${kind}${query}`, {
    credentials: 'include',
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(
      body && body.error && body.error.message
        ? body.error.message
        : `Request failed (${res.status})`,
    );
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = /filename="([^"]+)"/.exec(disposition);
  anchor.href = url;
  anchor.download = match ? match[1] : `logbanner-report-${kind}.${params.format || 'csv'}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

// Live feed over WebSocket. The access token goes in the `token`
// query parameter because a WebSocket handshake cannot carry an
// Authorization header. On a 4401 close the token is refreshed once
// and the socket reconnects; other drops reconnect with backoff
// (1s, doubling to a 30s cap). Returns a handle with close() and
// reconnect().
export function createLiveFeed({ onEvent, onStatus }) {
  let socket = null;
  let closed = false;
  let retryCount = 0;
  let timer = null;
  let refreshedOnce = false;

  function wsUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}/ws?token=${encodeURIComponent(getAccessToken() || '')}`;
  }

  function connect() {
    if (closed) {
      return;
    }
    onStatus('connecting');
    socket = new WebSocket(wsUrl());
    socket.onmessage = (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }
      onEvent(data);
    };
    socket.onopen = () => {
      retryCount = 0;
      refreshedOnce = false;
      onStatus('connected');
    };
    socket.onclose = async (event) => {
      socket = null;
      if (closed) {
        return;
      }
      if (event.code === 4401 && !refreshedOnce) {
        refreshedOnce = true;
        try {
          await refreshAccessToken();
          connect();
          return;
        } catch {
          onStatus('unauthorized');
          return;
        }
      }
      onStatus('reconnecting');
      const delay = Math.min(1000 * 2 ** retryCount, 30000);
      retryCount += 1;
      timer = setTimeout(connect, delay);
    };
    socket.onerror = () => {
      // onclose follows and drives the reconnect; nothing to do here.
    };
  }

  connect();

  return {
    close() {
      closed = true;
      if (timer) {
        clearTimeout(timer);
      }
      if (socket) {
        socket.close();
      }
    },
    reconnect() {
      if (socket) {
        socket.close();
      }
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      retryCount = 0;
      connect();
    },
  };
}
