CREATE TABLE rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT NOT NULL UNIQUE,
    source         TEXT NOT NULL,
    pattern        TEXT NOT NULL DEFAULT '',
    threshold      INTEGER NOT NULL CHECK (threshold > 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds > 0),
    ban_seconds    INTEGER NOT NULL CHECK (ban_seconds > 0),
    action         TEXT NOT NULL DEFAULT 'ban' CHECK (action IN ('ban', 'log')),
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    escalation     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
