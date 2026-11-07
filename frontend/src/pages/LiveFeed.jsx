import { useCallback, useEffect, useRef, useState } from 'react';
import { createLiveFeed } from '../api';
import Topbar from '../components/Topbar.jsx';

const MAX_ROWS = 200;

function rowTime(event) {
  const value = event.occurred_at || event.created_at || event.expires_at;
  if (!value) {
    return new Date().toLocaleTimeString();
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString();
}

function rowMessage(event) {
  if (event.message) {
    return event.message;
  }
  if (event.type === 'ban') {
    return `Ban ${event.dry_run ? '(simulated) ' : ''}${event.reason || ''}`.trim();
  }
  if (event.type === 'unban') {
    return 'Ban revoked';
  }
  return event.type;
}

export default function LiveFeed() {
  const [rows, setRows] = useState([]);
  const [paused, setPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [status, setStatus] = useState('connecting');
  const [filters, setFilters] = useState({ rule: '', ip: '', severity: '' });
  const [hello, setHello] = useState(null);
  const feedRef = useRef(null);
  const ruleFilterRef = useRef(null);
  const feedHandleRef = useRef(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    const handle = createLiveFeed({
      onEvent: (event) => {
        if (event.type === 'hello') {
          setHello(event.counts || null);
          return;
        }
        if (pausedRef.current) {
          return;
        }
        setRows((prev) => [...prev.slice(-(MAX_ROWS - 1)), { ...event, receivedAt: Date.now() }]);
      },
      onStatus: (next) => setStatus(next),
    });
    feedHandleRef.current = handle;
    return () => {
      handle.close();
      feedHandleRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (autoScroll && !paused && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [rows, autoScroll, paused]);

  // Shortcuts, active while the feed list has focus: p pauses or
  // resumes, / moves focus to the rule filter.
  const onFeedKeyDown = useCallback((event) => {
    if (event.key === 'p' || event.key === 'P') {
      event.preventDefault();
      setPaused((prev) => !prev);
    } else if (event.key === '/') {
      event.preventDefault();
      if (ruleFilterRef.current) {
        ruleFilterRef.current.focus();
      }
    }
  }, []);

  const visible = rows.filter((row) => {
    if (filters.rule && !(row.rule || '').toLowerCase().includes(filters.rule.toLowerCase())) {
      return false;
    }
    if (filters.ip && !(row.ip || '').includes(filters.ip)) {
      return false;
    }
    if (filters.severity && row.severity !== filters.severity) {
      return false;
    }
    return true;
  });

  return (
    <div className="app">
      <Topbar />
      <main className="page">
        <h1>Live feed</h1>
        <p className="page-status">
          <span className={`status-dot status-${status}`} aria-hidden="true" />
          {status === 'connected' && 'Connected — events arrive in real time.'}
          {status === 'connecting' && 'Connecting…'}
          {status === 'reconnecting' && 'Connection dropped — reconnecting…'}
          {status === 'unauthorized' &&
            'Session expired and refresh failed — sign in again to resume the feed.'}
          {hello && ` ${hello.events24h} events (24h), ${hello.activeBans} active bans.`}
        </p>
        <div className="feed-controls">
          <button type="button" onClick={() => setPaused((prev) => !prev)}>
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => feedHandleRef.current && feedHandleRef.current.reconnect()}
          >
            Reconnect
          </button>
          <label className="feed-check">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(event) => setAutoScroll(event.target.checked)}
            />
            Auto-scroll
          </label>
          <input
            ref={ruleFilterRef}
            className="feed-filter"
            type="text"
            placeholder="Filter by rule"
            value={filters.rule}
            onChange={(event) => setFilters((prev) => ({ ...prev, rule: event.target.value }))}
            aria-label="Filter by rule"
          />
          <input
            className="feed-filter"
            type="text"
            placeholder="Filter by IP"
            value={filters.ip}
            onChange={(event) => setFilters((prev) => ({ ...prev, ip: event.target.value }))}
            aria-label="Filter by IP"
          />
          <select
            className="feed-filter"
            value={filters.severity}
            onChange={(event) => setFilters((prev) => ({ ...prev, severity: event.target.value }))}
            aria-label="Filter by severity"
          >
            <option value="">All severities</option>
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="critical">critical</option>
          </select>
        </div>
        <p className="page-status feed-hint">
          Shortcuts (feed focused): p pause/resume, / focus rule filter.
        </p>
        {paused && <p className="page-status">Paused — new events are not shown until resumed.</p>}
        <div
          className="feed-list"
          ref={feedRef}
          tabIndex={0}
          onKeyDown={onFeedKeyDown}
          aria-label="Live events"
        >
          {visible.length === 0 ? (
            <p className="page-status">
              {rows.length === 0
                ? 'No events yet — detections and bans appear here as the agent publishes them.'
                : 'No events match the current filters.'}
            </p>
          ) : (
            <table className="dense-table feed-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>IP</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((row, index) => (
                  <tr key={`${row.receivedAt}-${index}`}>
                    <td className="mono">{rowTime(row)}</td>
                    <td>{row.type}</td>
                    <td>
                      <span className={`severity severity-${row.severity || 'none'}`}>
                        {row.severity || '—'}
                      </span>
                    </td>
                    <td>{row.rule || '—'}</td>
                    <td className="mono">{row.ip || '—'}</td>
                    <td>{rowMessage(row)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </main>
    </div>
  );
}
