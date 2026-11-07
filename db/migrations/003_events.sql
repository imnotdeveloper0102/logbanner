CREATE TABLE events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at TIMESTAMPTZ NOT NULL,
    source      TEXT NOT NULL,
    ip          INET,
    rule_id     UUID REFERENCES rules (id) ON DELETE SET NULL,
    severity    TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
    message     TEXT NOT NULL,
    raw         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX events_occurred_at_idx ON events (occurred_at DESC);
CREATE INDEX events_ip_idx ON events (ip);
CREATE INDEX events_rule_id_idx ON events (rule_id);
