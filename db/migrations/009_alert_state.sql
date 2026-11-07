-- Stage 7: alert state. The alert checker records what it has already
-- sent here so a repeated check (cron every 5 minutes, or a manual
-- POST /api/alerts/check) never sends the same alert twice, and so
-- the attack-wave alert can be throttled to at most one per hour.
-- Keys are free-form strings, e.g. 'critical_ban:<uuid>' with value
-- 'sent', or 'wave_alert_last_sent' with an ISO 8601 timestamp value.
CREATE TABLE alert_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
