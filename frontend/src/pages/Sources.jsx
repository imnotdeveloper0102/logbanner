import { useEffect, useState } from 'react';
import { fetchSources } from '../api';
import Topbar from '../components/Topbar.jsx';

export default function Sources() {
  const [sources, setSources] = useState([]);
  const [note, setNote] = useState('');
  const [agentStartedAt, setAgentStartedAt] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    fetchSources()
      .then((data) => {
        if (!cancelled) {
          setSources(data.sources || []);
          setNote(data.note || '');
          setAgentStartedAt(data.agent_started_at || null);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message || 'Could not load log sources');
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
  }, []);

  return (
    <div className="app">
      <Topbar />
      <main className="page">
        <h1>Log sources</h1>
        {agentStartedAt && (
          <p className="page-status">
            Agent started {new Date(agentStartedAt).toLocaleString()}. Counts refresh with the
            agent&apos;s 30-second summary tick.
          </p>
        )}
        {note && <p className="page-status">{note}</p>}
        {loading && <p className="page-status">Loading sources…</p>}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {!loading && sources.length === 0 && (
          <p className="page-status">
            No log sources configured, or the agent config could not be read.
          </p>
        )}
        {!loading && sources.length > 0 && (
          <section className="panel" aria-label="Log sources">
            <table className="dense-table">
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Format</th>
                  <th>Status</th>
                  <th>Lines read</th>
                  <th>Parsed</th>
                  <th>Unparsable</th>
                  <th>Last reported</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => (
                  <tr key={source.path}>
                    <td className="mono">{source.path}</td>
                    <td>{source.format || '—'}</td>
                    <td>
                      {source.status === 'reporting' && (
                        <span className="badge badge-enforced">reporting</span>
                      )}
                      {source.status === 'stale' && <span className="badge badge-sim">stale</span>}
                      {source.status === 'unavailable' && (
                        <span className="badge">unavailable</span>
                      )}
                    </td>
                    <td className="count">
                      {source.lines_read === null ? '—' : source.lines_read}
                    </td>
                    <td className="count">{source.parsed === null ? '—' : source.parsed}</td>
                    <td className="count">
                      {source.unparsable === null ? '—' : source.unparsable}
                    </td>
                    <td className="mono">
                      {source.last_reported_at
                        ? new Date(source.last_reported_at).toLocaleTimeString()
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="page-status">
              Counts come from the agent&apos;s status file, written every 30 seconds. A source with
              no report yet shows unavailable, never invented counts.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}
