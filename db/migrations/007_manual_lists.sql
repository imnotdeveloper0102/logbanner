CREATE TABLE manual_lists (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       TEXT NOT NULL CHECK (kind IN ('whitelist', 'blacklist')),
    value      TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);

CREATE INDEX manual_lists_kind_idx ON manual_lists (kind);
