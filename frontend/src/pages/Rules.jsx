import { useEffect, useState } from 'react';
import { fetchRules, updateRule } from '../api';
import { useAuth } from '../auth';
import Topbar from '../components/Topbar.jsx';

function RuleForm({ rule, onClose, onSaved }) {
  const [form, setForm] = useState({
    threshold: String(rule.threshold),
    window_seconds: String(rule.window_seconds),
    ban_seconds: String(rule.ban_seconds),
    action: rule.action,
    pattern: rule.pattern,
    escalation: (rule.escalation || [])
      .map((step) => (step === null ? '' : String(step)))
      .join(', '),
  });
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  function set(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function onSubmit(event) {
    event.preventDefault();
    setError('');
    const threshold = Number(form.threshold);
    const windowSeconds = Number(form.window_seconds);
    const banSeconds = Number(form.ban_seconds);
    if (!Number.isInteger(threshold) || threshold <= 0) {
      setError('Threshold must be a positive integer.');
      return;
    }
    if (!Number.isInteger(windowSeconds) || windowSeconds <= 0) {
      setError('Window must be a positive integer (seconds).');
      return;
    }
    if (!Number.isInteger(banSeconds) || banSeconds <= 0) {
      setError('Ban duration must be a positive integer (seconds).');
      return;
    }
    const escalationText = form.escalation.trim();
    let escalation;
    if (escalationText === '') {
      escalation = [];
    } else {
      escalation = [];
      for (const part of escalationText.split(',')) {
        const text = part.trim();
        if (text === '') {
          escalation.push(null);
        } else {
          const value = Number(text);
          if (!Number.isInteger(value) || value <= 0) {
            setError('Escalation steps must be positive integers, or empty for permanent.');
            return;
          }
          escalation.push(value);
        }
      }
    }
    setSaving(true);
    try {
      const data = await updateRule(rule.id, {
        threshold,
        window_seconds: windowSeconds,
        ban_seconds: banSeconds,
        action: form.action,
        pattern: form.pattern,
        escalation,
      });
      onSaved(data.rule, data.takes_effect);
    } catch (err) {
      // The server's syntax-check error arrives here verbatim, so
      // a bad regex is shown with its concrete message.
      setError(err.message || 'Could not save the rule');
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="rule-form">
      <div className="form-grid">
        <label>
          Threshold (events)
          <input
            type="text"
            inputMode="numeric"
            value={form.threshold}
            onChange={(event) => set('threshold', event.target.value)}
          />
        </label>
        <label>
          Window (seconds)
          <input
            type="text"
            inputMode="numeric"
            value={form.window_seconds}
            onChange={(event) => set('window_seconds', event.target.value)}
          />
        </label>
        <label>
          Ban duration (seconds)
          <input
            type="text"
            inputMode="numeric"
            value={form.ban_seconds}
            onChange={(event) => set('ban_seconds', event.target.value)}
          />
        </label>
        <label>
          Action
          <select value={form.action} onChange={(event) => set('action', event.target.value)}>
            <option value="ban">ban</option>
            <option value="log">log</option>
          </select>
        </label>
      </div>
      <label>
        Pattern
        <input
          className="mono"
          type="text"
          value={form.pattern}
          onChange={(event) => set('pattern', event.target.value)}
        />
      </label>
      <label>
        Escalation (seconds per repeat offence, comma-separated, empty = permanent)
        <input
          className="mono"
          type="text"
          placeholder="3600, 14400, 86400,"
          value={form.escalation}
          onChange={(event) => set('escalation', event.target.value)}
        />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="feed-controls">
        <button type="submit" disabled={saving}>
          {saving ? 'Saving…' : 'Save rule'}
        </button>
        <button type="button" className="btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}

export default function Rules() {
  const { user } = useAuth();
  const isAdmin = user && user.role === 'admin';
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [editing, setEditing] = useState(null);
  const [toggling, setToggling] = useState(null);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const data = await fetchRules();
      setRules(data.rules || []);
    } catch (err) {
      setError(err.message || 'Could not load rules');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function onToggle(rule) {
    setToggling(rule.id);
    setError('');
    setNotice('');
    try {
      const data = await updateRule(rule.id, { enabled: !rule.enabled });
      setRules((prev) => prev.map((r) => (r.id === rule.id ? data.rule : r)));
      setNotice(
        `Rule ${rule.name} ${data.rule.enabled ? 'enabled' : 'disabled'}. Takes effect ${data.takes_effect}.`,
      );
    } catch (err) {
      setError(err.message || 'Could not change the rule');
    } finally {
      setToggling(null);
    }
  }

  function onSaved(updated, takesEffect) {
    setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
    setEditing(null);
    setNotice(`Rule ${updated.name} saved. Takes effect ${takesEffect}.`);
  }

  return (
    <div className="app">
      <Topbar />
      <main className="page">
        <h1>Rules</h1>
        <p className="page-status">
          The rules table is the single source of truth. An edit here is what the agent runs after
          its next reload (SIGHUP) or restart; the YAML file only seeds rules that do not exist yet.
        </p>
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
        {loading && <p className="page-status">Loading rules…</p>}
        {!loading && rules.length === 0 && <p className="page-status">No rules defined.</p>}
        {!loading &&
          rules.map((rule) => (
            <section className="panel" key={rule.id} aria-label={`Rule ${rule.name}`}>
              <div className="rule-head">
                <div>
                  <h2 className="mono">{rule.name}</h2>
                  <p className="page-status">
                    source {rule.source} · threshold {rule.threshold} in {rule.window_seconds}s ·
                    ban {rule.ban_seconds}s · action {rule.action} · escalation{' '}
                    {(rule.escalation || [])
                      .map((step) => (step === null ? 'permanent' : `${step}s`))
                      .join(', ') || 'none'}
                  </p>
                  <p className="mono rule-pattern">{rule.pattern}</p>
                </div>
                {isAdmin && (
                  <div className="feed-controls">
                    <button
                      type="button"
                      className="btn-ghost"
                      disabled={toggling === rule.id}
                      onClick={() => onToggle(rule)}
                    >
                      {toggling === rule.id ? 'Saving…' : rule.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      type="button"
                      className="btn-ghost"
                      onClick={() => setEditing(editing === rule.id ? null : rule.id)}
                    >
                      {editing === rule.id ? 'Close editor' : 'Edit'}
                    </button>
                  </div>
                )}
              </div>
              {!rule.enabled && (
                <p className="page-status">Disabled — the agent skips this rule.</p>
              )}
              {isAdmin && editing === rule.id && (
                <RuleForm rule={rule} onClose={() => setEditing(null)} onSaved={onSaved} />
              )}
            </section>
          ))}
      </main>
    </div>
  );
}
