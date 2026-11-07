import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchCircuitBreaker, fetchStats } from '../api';
import Topbar from '../components/Topbar.jsx';

function hourlyLabel(hourIso) {
  const date = new Date(hourIso);
  return `${String(date.getHours()).padStart(2, '0')}:00`;
}

function HourlyChart({ data }) {
  const max = Math.max(1, ...data.map((d) => d.count));
  const width = 720;
  const height = 120;
  const barWidth = width / data.length;
  return (
    <svg
      className="chart"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label="Events per hour for the last 24 hours"
    >
      {data.map((d, i) => {
        const barHeight = Math.round((d.count / max) * (height - 20));
        return (
          <g key={d.hour}>
            <rect
              x={i * barWidth + 2}
              y={height - 20 - barHeight}
              width={barWidth - 4}
              height={barHeight}
              rx="1"
            >
              <title>
                {hourlyLabel(d.hour)}: {d.count} events
              </title>
            </rect>
            {i % 4 === 0 && (
              <text x={i * barWidth + 2} y={height - 5}>
                {hourlyLabel(d.hour)}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

function TopTable({ title, rows, emptyText, renderRow }) {
  return (
    <section className="panel" aria-label={title}>
      <h2>{title}</h2>
      {rows.length === 0 ? (
        <p className="page-status">{emptyText}</p>
      ) : (
        <table className="dense-table">
          <tbody>{rows.map(renderRow)}</tbody>
        </table>
      )}
    </section>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [breaker, setBreaker] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchStats()
      .then((data) => {
        if (!cancelled) {
          setStats(data);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message || 'Could not load statistics');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    // The breaker state is advisory: a failed fetch hides the
    // banner instead of breaking the dashboard.
    fetchCircuitBreaker()
      .then((data) => {
        if (!cancelled) {
          setBreaker(data);
        }
      })
      .catch(() => {
        // No banner; the dashboard still works without it.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const hasData = stats && (stats.events24h > 0 || stats.activeBans > 0);
  const hourly = stats ? stats.eventsByHour || [] : [];
  const topIps = stats ? stats.topIps || [] : [];
  const topRules = stats ? stats.topRules || [] : [];
  const topCountries = stats ? stats.topCountries || [] : [];

  return (
    <div className="app">
      <Topbar />
      <main className="page">
        <h1>Overview</h1>
        {breaker && breaker.open && (
          <section className="breaker-banner" role="alert">
            <strong>Circuit breaker open — automatic bans are paused</strong>
            <p>
              {breaker.bans_in_window} auto-bans in {breaker.window_seconds} seconds (max{' '}
              {breaker.max_bans}) tripped the breaker
              {breaker.opened_at ? ` at ${new Date(breaker.opened_at).toLocaleString()}` : ''}.
              Detections are still recorded, and manual bans still work. The breaker re-arms itself
              after its cooldown.
            </p>
          </section>
        )}
        {loading && <p className="page-status">Loading statistics…</p>}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {stats && (
          <>
            <section className="stat-grid" aria-label="Totals">
              <div className="stat">
                <span className="stat-label">Active bans</span>
                <span className="stat-value">{stats.activeBans}</span>
              </div>
              <div className="stat">
                <span className="stat-label">Events (24h)</span>
                <span className="stat-value">{stats.events24h}</span>
              </div>
              <div className="stat">
                <span className="stat-label">Rules enabled</span>
                <span className="stat-value">{stats.rulesEnabled}</span>
              </div>
              <div className="stat">
                <span className="stat-label">Users</span>
                <span className="stat-value">{stats.totalUsers}</span>
              </div>
            </section>
            {!hasData && (
              <section className="empty">
                <h2>No data yet</h2>
                <p>
                  No events have been recorded. The agent starts writing events in stage 3; until
                  then the counters above stay at zero.
                </p>
              </section>
            )}
            <section className="panel" aria-label="Events per hour">
              <h2>Events per hour (last 24h)</h2>
              {hourly.length === 0 ? (
                <p className="page-status">No hourly data yet.</p>
              ) : (
                <HourlyChart data={hourly} />
              )}
            </section>
            <div className="panel-grid">
              <TopTable
                title="Top IPs (24h)"
                rows={topIps}
                emptyText="No events in the last 24 hours."
                renderRow={(row) => (
                  <tr key={row.ip}>
                    <td className="mono">
                      <Link to={`/ips/${encodeURIComponent(row.ip)}`}>{row.ip}</Link>
                    </td>
                    <td className="count">{row.count}</td>
                  </tr>
                )}
              />
              <TopTable
                title="Top rules (24h)"
                rows={topRules}
                emptyText="No events in the last 24 hours."
                renderRow={(row) => (
                  <tr key={row.rule || 'no-rule'}>
                    <td>{row.rule || '(no rule)'}</td>
                    <td className="count">{row.count}</td>
                  </tr>
                )}
              />
              <TopTable
                title="Top countries (24h)"
                rows={topCountries}
                emptyText="No country data — GeoIP database not configured (see README, stage 6)."
                renderRow={(row) => (
                  <tr key={row.country}>
                    <td>{row.country}</td>
                    <td className="count">{row.count}</td>
                  </tr>
                )}
              />
            </div>
          </>
        )}
      </main>
    </div>
  );
}
