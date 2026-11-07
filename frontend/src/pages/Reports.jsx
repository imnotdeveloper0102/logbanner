import { useEffect, useState } from 'react';
import { downloadReport, fetchDailyReport, fetchWeeklyReport } from '../api';
import Topbar from '../components/Topbar.jsx';

function mondayOfThisWeek() {
  const today = new Date();
  const day = (today.getDay() + 6) % 7;
  const monday = new Date(today);
  monday.setDate(today.getDate() - day);
  return monday.toISOString().slice(0, 10);
}

export default function Reports() {
  const [kind, setKind] = useState('daily');
  const [date, setDate] = useState(() => new Date().toISOString().slice(0, 10));
  const [start, setStart] = useState(mondayOfThisWeek);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    const params = kind === 'daily' ? { date } : { start };
    const fetchFn = kind === 'daily' ? fetchDailyReport : fetchWeeklyReport;
    fetchFn(params)
      .then((data) => {
        if (!cancelled) {
          setReport(data.report || null);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.message || 'Could not load the report');
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
  }, [kind, date, start]);

  const bucketKey = report ? (kind === 'daily' ? 'events_by_hour' : 'events_by_day') : '';
  const bucketLabel = kind === 'daily' ? 'Hour' : 'Date';
  const bucketField = kind === 'daily' ? 'hour' : 'date';

  async function download(format) {
    setError('');
    try {
      const params = kind === 'daily' ? { date, format } : { start, format };
      await downloadReport(kind, params);
    } catch (err) {
      setError(err.message || 'Download failed');
    }
  }

  return (
    <div className="app">
      <Topbar />
      <main className="page">
        <h1>Reports</h1>
        <p className="page-status">
          Daily and weekly summaries from the admin service. Dates are UTC days; the weekly report
          covers 7 days from the start date.
        </p>
        <section className="panel" aria-label="Report options">
          <label>
            Report
            <select value={kind} onChange={(event) => setKind(event.target.value)}>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
          </label>{' '}
          {kind === 'daily' ? (
            <label>
              Date
              <input type="date" value={date} onChange={(event) => setDate(event.target.value)} />
            </label>
          ) : (
            <label>
              Week starts
              <input type="date" value={start} onChange={(event) => setStart(event.target.value)} />
            </label>
          )}{' '}
          <button className="btn" type="button" onClick={() => download('csv')}>
            Download CSV
          </button>{' '}
          <button className="btn" type="button" onClick={() => download('pdf')}>
            Download PDF
          </button>
        </section>
        {loading && <p className="page-status">Loading report…</p>}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {!loading && !error && report && (
          <>
            <section className="panel" aria-label="Report summary">
              <p>
                Period {report.period.start} to {report.period.end}. Total events:{' '}
                {report.total_events}. Bans created: {report.bans_created}. Bans revoked:{' '}
                {report.bans_revoked}.
              </p>
              {report.top_countries_note && (
                <p className="page-status">{report.top_countries_note}</p>
              )}
            </section>
            <section className="panel" aria-label="Events over time">
              <h2>Events</h2>
              <table className="dense-table">
                <thead>
                  <tr>
                    <th>{bucketLabel}</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {report[bucketKey].map((row) => (
                    <tr key={row[bucketField]}>
                      <td>{row[bucketField]}</td>
                      <td>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
            <section className="panel" aria-label="Top banned IPs">
              <h2>Top banned IPs</h2>
              {report.top_banned_ips.length === 0 ? (
                <p className="page-status">No bans in this period.</p>
              ) : (
                <table className="dense-table">
                  <thead>
                    <tr>
                      <th>IP</th>
                      <th>Bans</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.top_banned_ips.map((row) => (
                      <tr key={row.ip}>
                        <td className="mono">{row.ip}</td>
                        <td>{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
            <section className="panel" aria-label="Most triggered rules">
              <h2>Most triggered rules</h2>
              {report.most_triggered_rules.length === 0 ? (
                <p className="page-status">No events in this period.</p>
              ) : (
                <table className="dense-table">
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.most_triggered_rules.map((row, index) => (
                      <tr key={row.rule || `no-rule-${index}`}>
                        <td>{row.rule || '(no rule)'}</td>
                        <td>{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          </>
        )}
      </main>
    </div>
  );
}
