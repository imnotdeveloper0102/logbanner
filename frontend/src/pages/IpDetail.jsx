import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { addWhitelist, fetchIpDetail, revokeBan } from '../api';
import { useAuth } from '../auth';
import Topbar from '../components/Topbar.jsx';

function formatTime(value) {
  if (!value) {
    return '—';
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function IpDetail() {
  const { ip } = useParams();
  const { user } = useAuth();
  const isAdmin = user && user.role === 'admin';
  const [detail, setDetail] = useState(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [whitelistError, setWhitelistError] = useState('');
  const [whitelisting, setWhitelisting] = useState(false);
  const [revoking, setRevoking] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    fetchIpDetail(ip, { page, limit: 25 })
      .then((data) => {
        if (!cancelled) {
          setDetail(data);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message || 'Could not load IP detail');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [ip, page]);

  async function onWhitelist() {
    setWhitelistError('');
    setNotice('');
    setWhitelisting(true);
    try {
      await addWhitelist(ip, 'Whitelisted from the IP detail page');
      setNotice(
        `${ip} added to the manual whitelist. Future bans for it are refused by the gateway and the agent.`,
      );
      const data = await fetchIpDetail(ip, { page, limit: 25 });
      setDetail(data);
    } catch (err) {
      setWhitelistError(err.message || 'Could not add to the whitelist');
    } finally {
      setWhitelisting(false);
    }
  }

  async function onRevoke(ban) {
    setRevoking(ban.id);
    setError('');
    try {
      await revokeBan(ban.id);
      setNotice(`Ban for ${ban.ip} revoked.`);
      const data = await fetchIpDetail(ip, { page, limit: 25 });
      setDetail(data);
    } catch (err) {
      setError(err.message || 'Could not revoke the ban');
    } finally {
      setRevoking(null);
    }
  }

  const geo = detail ? detail.geo : null;
  const totalPages = detail ? Math.max(1, Math.ceil(detail.total / 25)) : 1;

  return (
    <div className="app">
      <Topbar />
      <main className="page">
        <h1>
          IP <span className="mono">{ip}</span>
        </h1>
        {notice && (
          <p className="notice" role="status">
            {notice}
          </p>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {loading && <p className="page-status">Loading IP detail…</p>}
        {detail && (
          <>
            <section className="stat-grid" aria-label="IP summary">
              <div className="stat">
                <span className="stat-label">Country</span>
                <span className="stat-value">
                  {geo && geo.country !== 'unknown' ? geo.country : 'unknown'}
                </span>
                <span className="stat-label">
                  {geo && geo.city
                    ? geo.city
                    : geo && !geo.database_available
                      ? 'No GeoIP database configured'
                      : 'No city data'}
                </span>
              </div>
              <div className="stat">
                <span className="stat-label">Total events</span>
                <span className="stat-value">{detail.total_events}</span>
              </div>
              <div className="stat">
                <span className="stat-label">First seen</span>
                <span className="stat-value stat-small">{formatTime(detail.first_seen)}</span>
              </div>
              <div className="stat">
                <span className="stat-label">Last seen</span>
                <span className="stat-value stat-small">{formatTime(detail.last_seen)}</span>
              </div>
            </section>
            <p className="page-status">
              {detail.whitelisted
                ? 'This IP is whitelisted — bans for it are refused.'
                : 'This IP is not whitelisted.'}
              {isAdmin && !detail.whitelisted && (
                <>
                  {' '}
                  <button
                    type="button"
                    className="btn-ghost"
                    disabled={whitelisting}
                    onClick={onWhitelist}
                  >
                    {whitelisting ? 'Adding…' : 'Add to whitelist'}
                  </button>
                </>
              )}
            </p>
            {whitelistError && (
              <p className="error" role="alert">
                {whitelistError}
              </p>
            )}
            <section className="panel" aria-label="Top rules for this IP">
              <h2>Top rules</h2>
              {detail.top_rules.length === 0 ? (
                <p className="page-status">No events recorded for this IP.</p>
              ) : (
                <table className="dense-table">
                  <tbody>
                    {detail.top_rules.map((row) => (
                      <tr key={row.rule || 'no-rule'}>
                        <td>{row.rule || '(no rule)'}</td>
                        <td className="count">{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
            <section className="panel" aria-label="Sample requests">
              <h2>Sample requests</h2>
              {detail.samples.length === 0 ? (
                <p className="page-status">No sample requests — no events recorded for this IP.</p>
              ) : (
                <table className="dense-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Rule</th>
                      <th>Request</th>
                      <th>Status</th>
                      <th>User-Agent</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.samples.map((sample, index) => (
                      <tr key={`${sample.occurred_at}-${index}`}>
                        <td className="mono">{formatTime(sample.occurred_at)}</td>
                        <td>{sample.rule || '—'}</td>
                        <td className="mono">
                          {sample.method || sample.path
                            ? `${sample.method || ''} ${sample.path || ''}`.trim()
                            : sample.raw || '—'}
                        </td>
                        <td className="mono">{sample.status || '—'}</td>
                        <td>{sample.user_agent || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
            <section className="panel" aria-label="Event history">
              <h2>Event history</h2>
              {detail.events.length === 0 ? (
                <p className="page-status">No events recorded for this IP.</p>
              ) : (
                <table className="dense-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Source</th>
                      <th>Severity</th>
                      <th>Rule</th>
                      <th>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.events.map((event) => (
                      <tr key={event.id}>
                        <td className="mono">{formatTime(event.occurred_at)}</td>
                        <td>{event.source}</td>
                        <td>
                          <span className={`severity severity-${event.severity || 'none'}`}>
                            {event.severity || '—'}
                          </span>
                        </td>
                        <td>{event.rule_name || '—'}</td>
                        <td>{event.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <div className="pagination">
                <button
                  type="button"
                  className="btn-ghost"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous
                </button>
                <span className="page-status">
                  Page {page} of {totalPages} ({detail.total} events)
                </span>
                <button
                  type="button"
                  className="btn-ghost"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </button>
              </div>
            </section>
            <section className="panel" aria-label="Ban history">
              <h2>Ban history</h2>
              {detail.bans.length === 0 ? (
                <p className="page-status">No bans for this IP.</p>
              ) : (
                <table className="dense-table">
                  <thead>
                    <tr>
                      <th>Reason</th>
                      <th>Rule</th>
                      <th>Created</th>
                      <th>Expires</th>
                      <th>Status</th>
                      <th aria-label="Actions" />
                    </tr>
                  </thead>
                  <tbody>
                    {detail.bans.map((ban) => (
                      <tr key={ban.id}>
                        <td>{ban.reason}</td>
                        <td>{ban.rule_name || '—'}</td>
                        <td className="mono">{formatTime(ban.created_at)}</td>
                        <td className="mono">{formatTime(ban.expires_at)}</td>
                        <td>
                          {ban.revoked_at ? (
                            <span className="badge">revoked</span>
                          ) : ban.dry_run ? (
                            <span className="badge badge-sim">simulated</span>
                          ) : (
                            <span className="badge badge-enforced">enforced</span>
                          )}
                        </td>
                        <td>
                          {isAdmin && !ban.revoked_at && (
                            <button
                              type="button"
                              className="btn-ghost"
                              disabled={revoking === ban.id}
                              onClick={() => onRevoke(ban)}
                            >
                              {revoking === ban.id ? 'Revoking…' : 'Unban'}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
            <p className="page-status">
              <Link to="/bans">Back to bans</Link>
            </p>
          </>
        )}
      </main>
    </div>
  );
}
