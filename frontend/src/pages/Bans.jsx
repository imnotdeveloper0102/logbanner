import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { createBan, fetchBans, revokeBan } from '../api';
import { useAuth } from '../auth';
import Topbar from '../components/Topbar.jsx';

function formatTime(value) {
  if (!value) {
    return 'permanent';
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function isExpired(ban) {
  return ban.expires_at && new Date(ban.expires_at).getTime() <= Date.now();
}

export default function Bans() {
  const { user } = useAuth();
  const isAdmin = user && user.role === 'admin';
  const [bans, setBans] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [includeRevoked, setIncludeRevoked] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [form, setForm] = useState({ ip: '', reason: '', duration: '' });
  const [formError, setFormError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [revoking, setRevoking] = useState(null);

  async function load(nextPage, nextIncludeRevoked) {
    setLoading(true);
    setError('');
    try {
      const data = await fetchBans({
        page: nextPage,
        limit: 25,
        include_revoked: nextIncludeRevoked ? 'true' : 'false',
      });
      setBans(data.bans || []);
      setTotal(data.total || 0);
    } catch (err) {
      setError(err.message || 'Could not load bans');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load(page, includeRevoked);
  }, [page, includeRevoked]);

  const visible = bans.filter((ban) => (search ? ban.ip.includes(search.trim()) : true));

  async function onCreate(event) {
    event.preventDefault();
    setFormError('');
    setNotice('');
    const ip = form.ip.trim();
    if (!ip) {
      setFormError('IP address is required.');
      return;
    }
    const duration = form.duration.trim();
    let durationSeconds = null;
    if (duration !== '') {
      durationSeconds = Number(duration);
      if (!Number.isInteger(durationSeconds) || durationSeconds <= 0) {
        setFormError('Duration must be a positive number of seconds, or empty for permanent.');
        return;
      }
    }
    setSubmitting(true);
    try {
      await createBan({ ip, reason: form.reason.trim(), durationSeconds });
      setForm({ ip: '', reason: '', duration: '' });
      setNotice(
        `Ban created for ${ip}. The agent applies it to the firewall unless it is in dry-run mode.`,
      );
      load(1, includeRevoked);
      setPage(1);
    } catch (err) {
      setFormError(err.message || 'Could not create the ban');
    } finally {
      setSubmitting(false);
    }
  }

  async function onRevoke(ban) {
    setRevoking(ban.id);
    setError('');
    setNotice('');
    try {
      await revokeBan(ban.id);
      setNotice(`Ban for ${ban.ip} revoked.`);
      load(page, includeRevoked);
    } catch (err) {
      setError(err.message || 'Could not revoke the ban');
    } finally {
      setRevoking(null);
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / 25));

  return (
    <div className="app">
      <Topbar />
      <main className="page">
        <h1>Bans</h1>
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
        {isAdmin && (
          <section className="panel" aria-label="Manual ban">
            <h2>Manual ban</h2>
            <form onSubmit={onCreate} className="form-grid">
              <label>
                IP address
                <input
                  className="mono"
                  type="text"
                  placeholder="203.0.113.5"
                  value={form.ip}
                  onChange={(event) => setForm((prev) => ({ ...prev, ip: event.target.value }))}
                />
              </label>
              <label>
                Reason
                <input
                  type="text"
                  placeholder="Manual block after review"
                  value={form.reason}
                  onChange={(event) => setForm((prev) => ({ ...prev, reason: event.target.value }))}
                />
              </label>
              <label>
                Duration (seconds, empty = permanent)
                <input
                  type="text"
                  inputMode="numeric"
                  placeholder="3600"
                  value={form.duration}
                  onChange={(event) =>
                    setForm((prev) => ({ ...prev, duration: event.target.value }))
                  }
                />
              </label>
              <div>
                <button type="submit" disabled={submitting}>
                  {submitting ? 'Banning…' : 'Ban IP'}
                </button>
              </div>
            </form>
            {formError && (
              <p className="error" role="alert">
                {formError}
              </p>
            )}
            <p className="page-status">
              Loopback, private ranges, and manual whitelist entries are refused. In dry-run mode
              the ban is recorded only and marked simulated.
            </p>
          </section>
        )}
        <section className="panel" aria-label="Ban list">
          <div className="feed-controls">
            <input
              className="feed-filter"
              type="text"
              placeholder="Search by IP"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              aria-label="Search bans by IP"
            />
            <label className="feed-check">
              <input
                type="checkbox"
                checked={includeRevoked}
                onChange={(event) => setIncludeRevoked(event.target.checked)}
              />
              Show revoked / expired
            </label>
          </div>
          {loading && <p className="page-status">Loading bans…</p>}
          {!loading && visible.length === 0 && (
            <p className="page-status">
              {bans.length === 0
                ? 'No bans yet — detections with action ban and manual bans appear here.'
                : 'No bans match the current search.'}
            </p>
          )}
          {!loading && visible.length > 0 && (
            <table className="dense-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Reason</th>
                  <th>Rule</th>
                  <th>Banned by</th>
                  <th>Created</th>
                  <th>Expires</th>
                  <th>Status</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {visible.map((ban) => (
                  <tr key={ban.id}>
                    <td className="mono">
                      <Link to={`/ips/${encodeURIComponent(ban.ip)}`}>{ban.ip}</Link>
                    </td>
                    <td>{ban.reason}</td>
                    <td>{ban.rule_name || '—'}</td>
                    <td className="mono">{ban.banned_by || '—'}</td>
                    <td className="mono">{formatTime(ban.created_at)}</td>
                    <td className="mono">{formatTime(ban.expires_at)}</td>
                    <td>
                      {ban.revoked_at ? (
                        <span className="badge">revoked</span>
                      ) : isExpired(ban) ? (
                        <span className="badge">expired</span>
                      ) : ban.dry_run ? (
                        <span className="badge badge-sim">simulated</span>
                      ) : (
                        <span className="badge badge-enforced">enforced</span>
                      )}
                    </td>
                    <td>
                      {isAdmin && !ban.revoked_at && !isExpired(ban) && (
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
              Page {page} of {totalPages} ({total} bans)
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
      </main>
    </div>
  );
}
